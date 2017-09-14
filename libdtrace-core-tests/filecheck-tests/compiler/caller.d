BEGIN
{
/*
 * CHECK: ldgs %r1, 273 ! DT_VAR(273) = "caller"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = caller;
}

