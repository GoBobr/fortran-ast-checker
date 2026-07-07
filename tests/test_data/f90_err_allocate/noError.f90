! Test file for F90.ERR.Allocate (Rule 5)
! This file should NOT trigger any violations.
module good_alloc_module
  implicit none

contains

  subroutine good_sub(arr, n, ierr)
    real, allocatable, intent(out) :: arr(:)
    integer, intent(in) :: n
    integer, intent(out) :: ierr

    allocate(arr(n), stat=ierr)
    if (ierr /= 0) return
  end subroutine good_sub

  subroutine good_dealloc(arr, ierr)
    real, allocatable, intent(inout) :: arr(:)
    integer, intent(out) :: ierr

    deallocate(arr, stat=ierr)
  end subroutine good_dealloc

end module good_alloc_module
