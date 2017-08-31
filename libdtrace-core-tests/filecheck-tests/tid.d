BEGIN
{
/*
 * CHECK: ldgs %rd, 279 ! DT_VAR(279) = "tid"
 * CHECK-NEXT: stgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %rd
 */
	x = tid;
}
