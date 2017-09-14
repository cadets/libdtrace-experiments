BEGIN
{
/*
 * CHECK: ldgs %r1, 286 ! DT_VAR(286) = "uid"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = uid;
}

