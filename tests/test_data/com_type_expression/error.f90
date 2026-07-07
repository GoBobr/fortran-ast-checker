! Test file for COM.TYPE.Expression (Rule 2)
! This file SHOULD trigger violations (mixed-type arithmetic).
module bad_type_module
  implicit none

contains

  subroutine bad_sub(a, b, c)
    integer, intent(in) :: a
    real, intent(in) :: b
    real, intent(out) :: c

    ! Mixed type: integer + real
    c = a + b
    ! Mixed type: real * integer
    c = b * a
  end subroutine bad_sub

end module bad_type_module
