BEGIN
{
/*
 * CHECK: ldgs %rd, 278 ! DT_VAR(278) = "pid"
 * CHECK-NEXT: stgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %rd
 */
	x = pid;
}
