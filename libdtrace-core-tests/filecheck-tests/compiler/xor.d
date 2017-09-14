BEGIN
{
/*
 * CHECK: setx %r1, 0 ! 0x2
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1

 * CHECK: setx %r1, 0 ! 0x1
 * CHECK-NEXT: stgs 1281, %r1 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: ret %r1

 * CHECK: ldgs %r1, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ldgs %r2, 1281 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: xor %r1, %r1, %r2
 * CHECK-NEXT: stgs 1282, %r1 ! DT_VAR(1282) = "z"
 * CHECK-NEXT: ret %r1
 */
	x = 2;
	y = 1;
	z = x ^ y;
}
