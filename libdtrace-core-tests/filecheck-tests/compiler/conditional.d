BEGIN
/execname == "test"/
{
/*
 * CHECK: ldgs %r1, 280 ! DT_VAR(280) = "execname"
 * CHECK-NEXT: sets %r2, 1 ! "test"
 * CHECK-NEXT: scmp %r1, %r2
 * CHECK-NEXT: be 6
 * CHECK-NEXT: mov %r1, %r0
 * CHECK-NEXT: ba 7
 * CHECK-NEXT: setx %r1, 0 ! 0x1
 * CHECK-NEXT: ret %r1
 *
 * CHECK: setx %r1, 0 ! 0x0
 * CHECK-NEXT: ret %r1
 */
	trace(0);
}
