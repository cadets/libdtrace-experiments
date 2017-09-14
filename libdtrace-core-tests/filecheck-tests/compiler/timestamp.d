BEGIN
{
/*
 * CHECK: ldgs %r1, 257 ! DT_VAR(257) = "timestamp"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = timestamp;
}

