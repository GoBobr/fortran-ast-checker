! Test file for COM.TYPE.Expression (Rule 2)
! This file should NOT trigger any violations.
module good_type_module
  implicit none

contains

  subroutine good_sub(a, b, c)
    integer, intent(in) :: a
    real, intent(in) :: b
    real, intent(out) :: c
    real :: d

    ! Same-type operations are OK
    d = b + b
    c = b * 2.0
    ! Explicit conversion is OK
    c = real(a) + b
    ! Same type operations
    d = b + 1.0
  end subroutine good_sub

end module good_type_module
