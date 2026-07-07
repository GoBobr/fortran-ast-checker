! Test file for F90.ERR.Allocate (Rule 5)
! This file SHOULD trigger violations (missing STAT= in ALLOCATE/DEALLOCATE).
module bad_alloc_module
  implicit none

contains

  subroutine bad_sub(arr, n)
    real, allocatable, intent(out) :: arr(:)
    integer, intent(in) :: n

    ! Missing STAT= in ALLOCATE
    allocate(arr(n))
  end subroutine bad_sub

  subroutine bad_dealloc(arr)
    real, allocatable, intent(inout) :: arr(:)

    ! Missing STAT= in DEALLOCATE
    deallocate(arr)
  end subroutine bad_dealloc

end module bad_alloc_module
