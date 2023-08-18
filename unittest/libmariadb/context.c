/*
 * Tests for ma_context functions.
 */

#include "my_test.h"
#include "mysql.h"
#include "ma_context.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Ensures the context system aligns the stack correctly for i386 and x86_64
 */
void async_task(__attribute__((unused)) void *v) {
#if defined( __GNUC__ ) && ( defined( __i386__ ) || defined( __x86_64__ ) )
    /*
     * The compiler assumes the stack is correctly aligned on a 16-byte
     * boundary on entry to the function (actually, with a return address
     * popped on top of the aligned address). Creating an object with a
     * max_align_t type should also be aligned at that boundary, so we should
     * be able to use movaps to move the first 128 bits into  xmm0.
     */
    union {
        max_align_t aligned;
        uint64_t data[2];
    } aligned;
    __asm__("movaps %0, %%xmm0" : : "m" (aligned.data) : "xmm0" );
#endif
}

static int test_stack_align() {
    struct my_context ctx;
    my_context_init(&ctx, 65536);
    my_context_spawn(&ctx, async_task, &ctx);
    my_context_destroy(&ctx);
    return 0;
}

int main()
{
    plan(1);
    ok( test_stack_align() == 0, "stack alignment check" );
}
