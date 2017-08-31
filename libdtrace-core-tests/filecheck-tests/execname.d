BEGIN
{
/*
 * CHECK: ldgs %rd, 280 ! DT_VAR(280) = "execname"
 * CHECK-NEXT: stgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %rd
 */
	x = execname;
}
