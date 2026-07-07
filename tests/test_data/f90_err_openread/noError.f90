! Test file for F90.ERR.OpenRead (Rule 3)
! This file should NOT trigger any violations.
module good_open_module
  implicit none

contains

  subroutine good_sub(filename, data, ierr)
    character(len=*), intent(in) :: filename
    integer, intent(out) :: data
    integer, intent(out) :: ierr
    integer :: unit

    open(unit=10, file=filename, status='old', action='read', iostat=ierr)
    if (ierr /= 0) return
    read(10, *, iostat=ierr) data
    close(10, iostat=ierr)
  end subroutine good_sub

end module good_open_module
