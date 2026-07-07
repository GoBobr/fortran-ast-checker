! Test file for COM.DATA.Initialisation (Rule 4)
! This file should NOT trigger any violations.
module good_init_module
  implicit none

contains

  subroutine good_sub(x, y, result)
    integer, intent(in) :: x
    integer, intent(in) :: y
    integer, intent(out) :: result
    integer :: temp

    temp = x + y
    result = temp * 2
  end subroutine good_sub

end module good_init_module
