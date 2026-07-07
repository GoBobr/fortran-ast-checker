! Test file for F90.ERR.OpenRead (Rule 3)
! This file SHOULD trigger violations (missing IOSTAT in OPEN).
module bad_open_module
  implicit none

contains

  subroutine bad_sub(filename, data)
    character(len=*), intent(in) :: filename
    integer, intent(out) :: data
    integer :: unit

    ! Missing IOSTAT= in OPEN
    open(unit=10, file=filename, status='old', action='read')
    read(10, *) data
    close(10)
  end subroutine bad_sub

end module bad_open_module
