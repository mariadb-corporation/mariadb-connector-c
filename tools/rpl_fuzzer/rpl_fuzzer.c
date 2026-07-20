#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <mysql.h>
#include <mariadb_rpl.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  /* 1. Set a safe baseline size limit */
  if (Size < 140 || Size > 1024 * 1024) return 0;

  MARIADB_RPL *rpl = mariadb_rpl_init(NULL);
  if (!rpl) return 0;

  /* 2. Allocate a mutable local buffer */
  uint8_t *mutable_payload = malloc(Size);
  if (!mutable_payload) {
    mariadb_rpl_close(rpl);
    return 0;
  }
  memcpy(mutable_payload, Data, Size);

  /* 3. Force the valid 4-byte binlog magic marker sequence */
  mutable_payload[0] = 0xFE;
  mutable_payload[1] = 0x62;
  mutable_payload[2] = 0x69;
  mutable_payload[3] = 0x6E;

  /* 4. Surgical bypass of the Format Description check */
  if (mutable_payload[8] == FORMAT_DESCRIPTION_EVENT) {
    mutable_payload[79] = 19;
  }

  /* 5. SURGICAL TABLE_MAP_EVENT SANITIZATION
   * Check if the second event is a Table Map. If it is, ensure its 
   * internal database name length doesn't cause an immediate parser rejection.
   */
  if (mutable_payload[107] == TABLE_MAP_EVENT) {
    // If the database name length byte is ridiculously large, clamp it safely
    if (mutable_payload[130] > 64) {
      mutable_payload[130] = 4;
    }
  }

  /* 6. Create an anonymous in-memory file descriptor */
  int fd = memfd_create("fuzz_binlog", MFD_CLOEXEC);
  if (fd < 0) {
    free(mutable_payload);
    mariadb_rpl_close(rpl);
    return 0;
  }

  /* Write our cleanly patched mutable payload directly down to the stream */
  if (write(fd, mutable_payload, Size) != (ssize_t)Size) {
    free(mutable_payload);
    close(fd);
    mariadb_rpl_close(rpl);
    return 0;
  }
  free(mutable_payload);

  /* Rewind the descriptor so the parser reads it from the beginning */
  lseek(fd, 0, SEEK_SET);

  /* Map the virtual file descriptor context into the process environment */
  char proc_filename[64];
  snprintf(proc_filename, sizeof(proc_filename), "/proc/self/fd/%d", fd);

  uint32_t uncompress = 0;
  uint32_t extract = 1;         
  uint32_t verify_checksum = 0;

  if (mariadb_rpl_optionsv(rpl, MARIADB_RPL_FILENAME, proc_filename, (size_t)0) == 0 &&
      mariadb_rpl_optionsv(rpl, MARIADB_RPL_UNCOMPRESS, &uncompress) == 0 &&
      mariadb_rpl_optionsv(rpl, MARIADB_RPL_VERIFY_CHECKSUM, &verify_checksum) == 0 &&
      mariadb_rpl_optionsv(rpl, MARIADB_RPL_EXTRACT_VALUES, &extract) == 0) {
    
    if (mariadb_rpl_open(rpl) == 0) {
      MARIADB_RPL_EVENT *event = NULL;
      MARIADB_RPL_EVENT *table_map_event = NULL;
      uint64_t current_table_id = 0; 

      while ((event = mariadb_rpl_fetch(rpl, NULL))) {
        
        if (event->event_type == TABLE_MAP_EVENT) {
          if (table_map_event)
            mariadb_free_rpl_event(table_map_event);
          
          table_map_event = event;
          
          if (event->raw_data_size >= 19 + 6 && event->raw_data != NULL) {
            current_table_id = 0;
            memcpy(&current_table_id, event->raw_data + 19, 6);
          }
          continue;
        }

        if (event->event_type == WRITE_ROWS_EVENT_V1 ||
            event->event_type == UPDATE_ROWS_EVENT_V1 ||
            event->event_type == DELETE_ROWS_EVENT_V1 ||
            event->event_type == WRITE_ROWS_COMPRESSED_EVENT_V1 ||
            event->event_type == UPDATE_ROWS_COMPRESSED_EVENT_V1 ||
            event->event_type == DELETE_ROWS_COMPRESSED_EVENT_V1 ||
            event->event_type == WRITE_ROWS_EVENT ||
            event->event_type == UPDATE_ROWS_EVENT ||
            event->event_type == DELETE_ROWS_EVENT) {

          if (table_map_event && current_table_id != 0) {
            if (event->raw_data_size >= 19 + 6 && event->raw_data != NULL) {
              memcpy(event->raw_data + 19, &current_table_id, 6);
            }

            MARIADB_RPL_ROW *rpl_row = mariadb_rpl_extract_rows(rpl, table_map_event, event);
            if (rpl_row) {
              /* Target boundary hit. */
            }
          }
        }
        mariadb_free_rpl_event(event);
      }
      if (table_map_event)
        mariadb_free_rpl_event(table_map_event);
    }
  }

  close(fd);
  mariadb_rpl_close(rpl);
  return 0;
}
