#include "proto_to_ruby.h"

using namespace ruby_fuzzer;

std::string protoConverter::removeSpecial(const std::string &x)
{
	std::string tmp(x);
	if (!tmp.empty())
		tmp.erase(std::remove_if(tmp.begin(), tmp.end(),
		                         [](char c) { return !(std::isalpha(c) || std::isdigit(c)); } ), tmp.end());
	return tmp;
}

void protoConverter::visit(ArrType const& x)
{
	if (x.elements_size() > 0) {
		int i = x.elements_size();
		m_output << "[";
		for (auto &e : x.elements()) {
			i--;
			if (i == 0) {
				visit(e);
			} else {
				visit(e);
				m_output << ", ";
			}
		}
		m_output << "]";
	} else {
		m_output << "[1]";
	}
}

void protoConverter::visit(Array const& x)
{
	switch (x.arr_func()) {
		case Array::FLATTEN:
			visit(x.arr_arg());
			m_output << ".flatten";
			break;
		case Array::COMPACT:
			visit(x.arr_arg());
			m_output << ".compact";
			break;
		case Array::FETCH:
			visit(x.arr_arg());
			m_output << ".fetch";
			break;
		case Array::FILL:
			visit(x.arr_arg());
			m_output << ".fill";
			break;
		case Array::ROTATE:
			visit(x.arr_arg());
			m_output << ".rotate";
			break;
		case Array::ROTATE_E:
			visit(x.arr_arg());
			m_output << ".rotate!";
			break;
		case Array::DELETEIF:
			visit(x.arr_arg());
			m_output << ".delete_if";
			break;
		case Array::INSERT:
			visit(x.arr_arg());
			m_output << ".insert";
			break;
		case Array::BSEARCH:
			visit(x.arr_arg());
			m_output << ".bsearch";
			break;
		case Array::KEEPIF:
			visit(x.arr_arg());
			m_output << ".keep_if";
			break;
		case Array::SELECT:
			visit(x.arr_arg());
			m_output << ".select";
			break;
		case Array::VALUES_AT:
			visit(x.arr_arg());
			m_output << ".values_at";
			break;
		case Array::BLOCK:
			visit(x.arr_arg());
			m_output << ".index";
			break;
		case Array::DIG:
			visit(x.arr_arg());
			m_output << ".dig";
			break;
		case Array::SLICE:
			visit(x.arr_arg());
			m_output << ".slice";
			break;
		case Array::PERM:
			visit(x.arr_arg());
			m_output << ".permutation";
			break;
		case Array::COMB:
			visit(x.arr_arg());
			m_output << ".combination";
			break;
		case Array::ASSOC:
			visit(x.arr_arg());
			m_output << ".assoc";
			break;
		case Array::RASSOC:
			visit(x.arr_arg());
			m_output << ".rassoc";
			break;
	}
	m_output << "(";
	visit(x.val_arg());
	m_output << ")";
}

void protoConverter::visit(AssignmentStatement const& x)
{
	m_output << "var_" << m_numLiveVars << " = ";
	visit(x.rvalue());
	m_numVarsPerScope.top()++;
	m_numLiveVars++;
	m_output << "\n";
}

void protoConverter::visit(BinaryOp const& x)
{
	m_output << "(";
	visit(x.left());
	switch (x.op()) {
		case BinaryOp::ADD: m_output << " + "; break;
		case BinaryOp::SUB: m_output << " - "; break;
		case BinaryOp::MUL: m_output << " * "; break;
		case BinaryOp::DIV: m_output << " / "; break;
		case BinaryOp::MOD: m_output << " % "; break;
		case BinaryOp::XOR: m_output << " ^ "; break;
		case BinaryOp::AND: m_output << " and "; break;
		case BinaryOp::OR: m_output << " or "; break;
		case BinaryOp::EQ: m_output << " == "; break;
		case BinaryOp::NE: m_output << " != "; break;
		case BinaryOp::LE: m_output << " <= "; break;
		case BinaryOp::GE: m_output << " >= "; break;
		case BinaryOp::LT: m_output << " < "; break;
		case BinaryOp::GT: m_output << " > "; break;
		case BinaryOp::RS: m_output << " >> "; break;
	}
	visit(x.right());
	m_output << ")";
}

void protoConverter::visit(BuiltinFuncs const& x)
{
	switch (x.bifunc_oneof_case()) {
		case BuiltinFuncs::kOs:
			visit(x.os());
			break;
		case BuiltinFuncs::kTime:
			visit(x.time());
			break;
		case BuiltinFuncs::kArr:
			visit(x.arr());
			break;
		case BuiltinFuncs::kMops:
			visit(x.mops());
			break;
		case BuiltinFuncs::BIFUNC_ONEOF_NOT_SET:
			m_output << "1";
			break;
	}
	m_output << "\n";
}

void protoConverter::visit(Const const& x)
{
	switch (x.const_oneof_case()) {
		case Const::kIntLit:
			m_output << "(" << (x.int_lit() % 13) << ")";
			break;
		case Const::kBoolVal:
			m_output << "(" << x.bool_val() << ")";
			break;
		case Const::CONST_ONEOF_NOT_SET:
			m_output << "1";
			break;
	}
}

void protoConverter::visit(Function const& x)
{
	m_output << "def foo()\nvar_0 = 1\n";
	visit(x.statements());
	m_output << "end\n";
	m_output << "foo\n";
}

void protoConverter::visit(HashType const& x)
{
	if (x.keyval_size() > 0) {
		int i = x.keyval_size();
		m_output << "{";
		for (auto &e : x.keyval()) {
			i--;
			if (i == 0) {
				visit(e);
			}
			else {
				visit(e);
				m_output << ", ";
			}
		}
		m_output << "}";
	}
}

void protoConverter::visit(IfElse const& x)
{
	m_output << "if ";
	visit(x.cond());
	m_output << "\n";
	visit(x.if_body());
	m_output << "\nelse\n";
	visit(x.else_body());
	m_output << "\nend\n";
}

void protoConverter::visit(KVPair const& x)
{
	m_output << "\"" << removeSpecial(x.key()) << "\"";
	m_output << " => ";
	m_output << "\"" << removeSpecial(x.val()) << "\"";
}

void protoConverter::visit(MathConst const& x)
{
	switch (x.math_const()) {
		case MathConst::PI:
			m_output << "Math::PI";
			break;
		case MathConst::E:
			m_output << "Math::E";
			break;
	}
}

void protoConverter::visit(MathOps const& x)
{
	switch (x.math_op()) {
		case MathOps::CBRT:
			m_output << "Math.cbrt(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::COS:
			m_output << "Math.cos(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::ERF:
			m_output << "Math.erf(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::ERFC:
			m_output << "Math.erfc(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::LOG:
			m_output << "Math.log(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::LOG10:
			m_output << "Math.log10(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::LOG2:
			m_output << "Math.log2(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::SIN:
			m_output << "Math.sin(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::SQRT:
			m_output << "Math.sqrt(";
			visit(x.math_arg());
			m_output << ")";
			break;
		case MathOps::TAN:
			m_output << "Math.tan(";
			visit(x.math_arg());
			m_output << ")";
			break;
	}
}

void protoConverter::visit(MathType const& x)
{
	switch (x.math_arg_oneof_case()) {
		case MathType::kMathRval:
			visit(x.math_rval());
			break;
		case MathType::kMathConst:
			visit(x.math_const());
			break;
		case MathType::MATH_ARG_ONEOF_NOT_SET:
			m_output << "1";
			break;
	}
}

void protoConverter::visit(ObjectSpace const& x)
{
	switch (x.os_func()) {
		case ObjectSpace::COUNT:
			m_output << "ObjectSpace.count_objects";
			break;
	}
	m_output << "(";
	visit(x.os_arg());
	m_output << ")" << "\n";
}

void protoConverter::visit(Rvalue const& x)
{
	switch (x.rvalue_oneof_case()) {
		case Rvalue::kVarref:
			visit(x.varref());
			break;
		case Rvalue::kCons:
			visit(x.cons());
			break;
		case Rvalue::kBinop:
			visit(x.binop());
			break;
		case Rvalue::RVALUE_ONEOF_NOT_SET:
			m_output << "1";
			break;
	}
}

void protoConverter::visit(Statement const& x)
{
	switch (x.stmt_oneof_case()) {
		case Statement::kAssignment:
			visit(x.assignment());
			break;
		case Statement::kIfelse:
			visit(x.ifelse());
			break;
		case Statement::kTernaryStmt:
			visit(x.ternary_stmt());
			break;
		case Statement::kBuiltins:
			visit(x.builtins());
			break;
		case Statement::kBlockstmt:
			visit(x.blockstmt());
			break;
		case Statement::STMT_ONEOF_NOT_SET:
			break;
	}
	m_output << "\n";
}

void protoConverter::visit(StatementSeq const& x)
{
	if (x.statements_size() > 0) {
		m_numVarsPerScope.push(0);
		m_output << "@scope ||= begin\n";
		for (auto &st : x.statements())
			visit(st);
		m_output << "end\n";
		m_numLiveVars -= m_numVarsPerScope.top();
		m_numVarsPerScope.pop();
	}
}

void protoConverter::visit(StringExtNoArg const& x)
{
	m_output << "\"" << removeSpecial(x.str_arg()) << "\"";
	switch (x.str_op()) {
		case StringExtNoArg::DUMP:
			m_output << ".dump";
			break;
		case StringExtNoArg::STRIP:
			m_output << ".strip";
			break;
		case StringExtNoArg::LSTRIP:
			m_output << ".lstrip";
			break;
		case StringExtNoArg::RSTRIP:
			m_output << ".rstrip";
			break;
		case StringExtNoArg::STRIPE:
			m_output << ".strip!";
			break;
		case StringExtNoArg::LSTRIPE:
			m_output << ".lstrip!";
			break;
		case StringExtNoArg::RSTRIPE:
			m_output << ".rstrip!";
			break;
		case StringExtNoArg::SWAPCASE:
			m_output << ".swapcase";
			break;
		case StringExtNoArg::SWAPCASEE:
			m_output << ".swapcase!";
			break;
		case StringExtNoArg::SQUEEZE:
			m_output << ".squeeze";
			break;
	}
}

void protoConverter::visit(Ternary const& x)
{
	m_output << "(";
	visit(x.tern_cond());
	m_output << " ? ";
	visit(x.t_branch());
	m_output << " : ";
	visit(x.f_branch());
	m_output << ")\n";
}

void protoConverter::visit(Time const& x)
{
	switch (x.t_func()) {
		case Time::AT:
			m_output << "Time.at";
			break;
		case Time::GM:
			m_output << "Time.gm";
			break;
	}
	m_output << "(" << (x.t_arg()% 13) << ")" << "\n";
}

void protoConverter::visit(VarRef const& x)
{
	m_output << "var_" << (static_cast<uint32_t>(x.varnum()) % m_numLiveVars);
}

std::string protoConverter::FunctionToString(Function const& input)
{
	visit(input);
	return m_output.str();
}
