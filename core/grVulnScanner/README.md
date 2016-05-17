E-THAPS: Enhanced THAPS
=======

Adding new detect machanism process
-----------
Handle built-in function nodes (PHPParser_Node_Expr_FuncCall): define how a vulnerability should be detected with new vulnerable sinks and corresponding securing functions.

Handle user defined function nodes (PHPParser_Node_Expr_MethodCall): include new variables in variable storage to all user defined function types.

Handle variable nodes (PHPParser_Node_Expr_Variable): consider whether variable comes from user input (GET, POST, COOKIE, REQUEST super-global variable), if yes, mark it as tainted for all new variables in variable storage.

Handle array variable nodes (PHPParser_Node_Expr_ArrayDimFetch): consider whether array variable comes from user input (GET, POST super-global variable), if yes, mark every element inside it as tainted for all new variables in variable storage.

Handle other insignificant nodes: contain other modifications to other nodes:

	*Conditional nodes (PHPParser_Node_Stmt_If|Elseif|Else)
	*Looping nodes (PHPParser_Node_Stmt_For|While|Foreach)
	*Logical nodes (PHPParser_Node_Expr_LogicalOr|And|Xor)
	*Casting nodes (PHPParser_Node_Expr_Cast_Bool|Int|Double)
	*Concat nodes (PHPParser_Node_Expr_Concat)
	*Assigning concat nodes (PHPParser_Node_Expr_AssignConcat)
	*Scalar Encapsed nodes (PHPParser_Node_Scalar_Encapsed)
	*Assigning plus node (PHPParser_Node_Expr_AssignPlus)
	*Static function (in class) nodes (PHPParser_Node_Expr_StaticCall)
	*Return nodes (PHPParser_Node_Stmt_Return)

