! Test file for COM.DESIGN.Alloc (Rule 9)
! This file should NOT trigger any violations.
module good_alloc_design_module
  implicit none

contains

  subroutine init_data(arr, n, ierr)
    real, allocatable, intent(out) :: arr(:)
    integer, intent(in) :: n
    integer, intent(out) :: ierr

    allocate(arr(n), stat=ierr)
  end subroutine init_data

  subroutine cleanup_data(arr, ierr)
    real, allocatable, intent(inout) :: arr(:)
    integer, intent(out) :: ierr

    deallocate(arr, stat=ierr)
  end subroutine cleanup_data

end module good_alloc_design_module
