! Test file for COM.FLOW.Exit (Rule 8)
! This file should NOT trigger any violations.
module good_exit_module
  implicit none

contains

  subroutine good_sub(ierr)
    integer, intent(out) :: ierr

    ierr = 0
    ! Single RETURN (or no RETURN) is OK
    ! Error-handling RETURNs inside IF blocks are OK
    if (ierr /= 0) return
  end subroutine good_sub

  subroutine good_sub2(ierr)
    integer, intent(out) :: ierr

    ierr = 0
    ! No RETURN at all — single exit point
  end subroutine good_sub2

end module good_exit_module
