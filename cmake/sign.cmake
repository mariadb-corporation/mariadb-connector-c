MACRO(SIGN_TARGET target)
  SET(target_file $<TARGET_FILE:${target}>)
  ADD_CUSTOM_COMMAND(TARGET ${target} POST_BUILD
                     DEPENDS ${target}
                     COMMAND signtool ARGS sign ${SIGN_OPTIONS} ${target_file})
ENDMACRO()
