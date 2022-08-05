#include <cstdint>
#include <cstddef>
#include <string>
#include <ostream>
#include <sstream>
#include <stack>
#include <ruby.pb.h>

namespace ruby_fuzzer {
	class protoConverter
	{
	public:
		protoConverter() {
			m_numLiveVars = 1;
			m_numVarsPerScope.push(m_numLiveVars);
		}
		protoConverter(protoConverter const& x) {
			m_numLiveVars = x.m_numLiveVars;
			m_numVarsPerScope = x.m_numVarsPerScope;
		}
		~protoConverter() {}
		std::string FunctionToString(Function const& _input);

	private:
		void visit(ArrType const&);
		void visit(Array const&);
		void visit(AssignmentStatement const&);
		void visit(BinaryOp const&);
		void visit(BuiltinFuncs const&);
		void visit(Const const&);
		void visit(Function const&);
		void visit(HashType const&);
		void visit(IfElse const&);
		void visit(KVPair const&);
		void visit(MathConst const&);
		void visit(MathOps const&);
		void visit(MathType const&);
		void visit(ObjectSpace const&);
		void visit(Rvalue const&);
		void visit(Statement const&);
		void visit(StatementSeq const&);
		void visit(StringExtNoArg const&);
		void visit(Ternary const&);
		void visit(Time const&);
		void visit(VarRef const&);
		template <class T>
		void visit(google::protobuf::RepeatedPtrField<T> const& _repeated_field);

		std::string removeSpecial(const std::string &x);

		std::ostringstream m_output;
		std::stack<uint8_t> m_numVarsPerScope;
		int32_t m_numLiveVars;
	};
}
