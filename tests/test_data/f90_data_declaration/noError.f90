! Test file for F90.DATA.Declaration (Rule 1)
! This file should NOT trigger any violations.
module good_module
  implicit none
  private
  public :: good_sub

contains

  subroutine good_sub(x, y, arr)
    implicit none
    integer, intent(in) :: x
    real, intent(out) :: y
    real, intent(inout), allocatable :: arr(:)
    integer :: i
    real :: pi = 3.14159

    do i = 1, x
      arr(i) = arr(i) * pi
    end do
    y = arr(x)
  end subroutine good_sub

end module good_module
