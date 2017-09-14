BEGIN
{
/*
 * CHECK: setx %r1, 0 ! 0x3
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: setx %r1, 0 ! 0x4
 * CHECK-NEXT: stgs 1281, %r1 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: setx %r2, 0 ! 0x1
 * CHECK-NEXT: sll %r1, %r1, %r2
 * CHECK-NEXT: ldgs %r2, 1281 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: setx %r3, 1 ! 0x2
 * CHECK-NEXT: sll %r2, %r2, %r3
 * CHECK-NEXT: xor %r1, %r1, %r2
 * CHECK-NEXT: ldgs %r2, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ldgs %r3, 1281 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: and %r2, %r2, %r3
 * CHECK-NEXT: setx %r3, 2 ! 0x3
 * CHECK-NEXT: sra %r2, %r2, %r3
 * CHECK-NEXT: ldgs %r3, 1281 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: not %r3, %r3
 * CHECK-NEXT: and %r2, %r2, %r3
 * CHECK-NEXT: or %r1, %r1, %r2
 * CHECK-NEXT: stgs 1282, %r1 ! DT_VAR(1282) = "z"
 * CHECK-NEXT: ret %r1
 */
	x = 3;
	y = 4;

	z = ((x << 1) ^ (y << 2)) | ((x & y) >> 3) & (~y)
}
