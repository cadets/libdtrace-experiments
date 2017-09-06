BEGIN
{
/*
 * CHECK: ldgs %r1, 262 ! DT_VAR(262) = "arg0"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 263 ! DT_VAR(263) = "arg1"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 264 ! DT_VAR(264) = "arg2"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 265 ! DT_VAR(265) = "arg3"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 266 ! DT_VAR(266) = "arg4"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 267 ! DT_VAR(267) = "arg5"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 268 ! DT_VAR(268) = "arg6"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 269 ! DT_VAR(269) = "arg7"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 270 ! DT_VAR(270) = "arg8"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 271 ! DT_VAR(271) = "arg9"
 * CHECK-NEXT: ret %r1
 */


	trace(arg0);
	trace(arg1);
	trace(arg2);
	trace(arg3);
	trace(arg4);
	trace(arg5);
	trace(arg6);
	trace(arg7);
	trace(arg8);
	trace(arg9);
}
