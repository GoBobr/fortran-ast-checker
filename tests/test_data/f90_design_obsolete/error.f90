! Test file for F90.DESIGN.Obsolete (Rule 7)
! This file SHOULD trigger violations (CONTINUE statement, ENTRY statement).
module bad_obsolete_module
  implicit none

contains

  subroutine bad_sub(n, result)
    integer, intent(in) :: n
    integer, intent(out) :: result
    integer :: i

    do i = 1, n
      result = result + i
      ! CONTINUE is obsolete
      continue
    end do
  end subroutine bad_sub

  ! ENTRY is obsolete
  subroutine parent_sub()
    integer :: x
    x = 0
  entry child_sub()
    x = x + 1
  end subroutine parent_sub

end module bad_obsolete_module
