! Test file for COM.DATA.Initialisation (Rule 4)
! This file SHOULD trigger violations (variable used before initialization).
module bad_init_module
  implicit none

contains

  subroutine bad_sub(x, result)
    integer, intent(in) :: x
    integer, intent(out) :: result
    integer :: temp

    ! 'temp' used before being assigned
    result = temp + x
    temp = 10
  end subroutine bad_sub

end module bad_init_module
