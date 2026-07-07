! Test file for COM.DATA.FloatCompare (Rule 6)
! This file should NOT trigger any violations.
module good_float_module
  implicit none

contains

  subroutine good_sub(x, y, result)
    real, intent(in) :: x, y
    integer, intent(out) :: result
    integer :: i

    ! Integer comparison is OK
    if (i == 0) then
      result = 1
    end if

    ! Using relational operators (<, >, <=, >=) on reals is OK
    if (x > y) then
      result = 2
    end if
  end subroutine good_sub

end module good_float_module
