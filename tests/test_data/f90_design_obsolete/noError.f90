! Test file for F90.DESIGN.Obsolete (Rule 7)
! This file should NOT trigger any violations.
module good_obsolete_module
  implicit none

contains

  subroutine good_sub(n, result)
    integer, intent(in) :: n
    integer, intent(out) :: result
    integer :: i

    ! Integer DO loop variable is OK
    do i = 1, n
      result = result + i
    end do
  end subroutine good_sub

end module good_obsolete_module
