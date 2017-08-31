unsigned x;
unsigned y;
unsigned z;

/*
 * It is worth noting that SRL only happens on *unsigned* variables. Signed
 * variables can only ever be shifted arithmetically.
 */
BEGIN
{
/*
 * CHECK: setx %rd, 0 ! 0x2
 * CHECK-NEXT: stgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %rd

 * CHECK: setx %rd, 0 ! 0x1
 * CHECK-NEXT: stgs %rd, 1281 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: ret %rd

 * CHECK: ldgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ldgs %rd, 1281 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: srl %rd, %r1, %r2
 * CHECK-NEXT: stgs %rd, 1282 ! DT_VAR(1282) = "z"
 * CHECK-NEXT: ret %rd
 */
	x = 2;
	y = 1;
	z = x >> y;
}
