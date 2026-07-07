! Test file for F90.DATA.Declaration (Rule 1)
! This file SHOULD trigger violations (missing IMPLICIT NONE, undeclared variables).
module bad_module
  ! Missing IMPLICIT NONE

contains

  subroutine bad_sub(x, y)
    integer :: x
    real :: y
    ! 'z' is not declared
    z = x + y
    ! 'w' is not declared
    call inner_call(w)
  end subroutine bad_sub

end module bad_module
