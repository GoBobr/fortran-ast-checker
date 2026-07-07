! Test file for COM.DATA.FloatCompare (Rule 6)
! This file SHOULD trigger violations (floating-point == and /= comparisons).
module bad_float_module
  implicit none

contains

  subroutine bad_sub(x, y, result)
    real, intent(in) :: x, y
    integer, intent(out) :: result

    ! Floating-point == comparison
    if (x == y) then
      result = 1
    end if

    ! Floating-point /= comparison
    if (x /= y) then
      result = 2
    end if
  end subroutine bad_sub

end module bad_float_module
