! Test file for F90.DATA.ArrayAccess (Rule 10)
! This file should NOT trigger any violations.
module good_array_module
  implicit none

contains

  subroutine good_sub(arr, n)
    real, intent(inout) :: arr(:)
    integer, intent(in) :: n
    integer :: i

    ! Direct array assignment is OK
    do i = 1, n
      arr(i) = arr(i) * 2.0
    end do
  end subroutine good_sub

end module good_array_module
