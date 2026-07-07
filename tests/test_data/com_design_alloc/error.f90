! Test file for COM.DESIGN.Alloc (Rule 9)
! This file SHOULD trigger violations (allocated but never deallocated).
module bad_alloc_design_module
  implicit none

contains

  subroutine process_data(arr, n, ierr)
    real, allocatable, intent(out) :: arr(:)
    integer, intent(in) :: n
    integer, intent(out) :: ierr

    ! Allocated but never deallocated (not in init/cleanup pattern)
    allocate(arr(n), stat=ierr)
  end subroutine process_data

end module bad_alloc_design_module
