! Test file for COM.FLOW.Exit (Rule 8)
! This file SHOULD trigger violations (RETURN in normal flow, not error handling).
module bad_exit_module
  implicit none

contains

  subroutine bad_sub(x, y)
    integer, intent(in) :: x
    integer, intent(out) :: y

    y = x * 2
    ! RETURN in normal flow (not inside an IF block, not last statement)
    return
    y = y + 1
  end subroutine bad_sub

end module bad_exit_module
