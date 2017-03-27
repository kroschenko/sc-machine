/*
* This source file is part of an OSTIS project. For the latest info, see http://ostis.net
* Distributed under the MIT License
* (See accompanying file COPYING.MIT or copy at http://opensource.org/licenses/MIT)
*/

#include "sc_agent.hpp"

#include "../sc_debug.hpp"

namespace
{

bool gInitializeResult = false;
bool gIsInitialized = false;

} // namespace

bool ScAgentInit(bool force /* = false */)
{
  if (force || !gIsInitialized)
  {
    gInitializeResult = ScAgentAction::InitGlobal();
    gIsInitialized = true;
  }

  return gInitializeResult;
}


ScAgent::ScAgent(char const * name, sc_uint8 accessLvl)
  : m_memoryCtx(accessLvl, name)
{
}

ScAgent::~ScAgent()
{
}

sc_result ScAgent::Run(ScAddr const & listenAddr, ScAddr const & edgeAddr, ScAddr const & otherAddr)
{
  return SC_RESULT_ERROR;
}


// ---------------------------
ScAgentAction::ScAgentAction(ScAddr const & cmdClassAddr, char const * name, sc_uint8 accessLvl)
  : ScAgent(name, accessLvl)
  , m_cmdClassAddr(cmdClassAddr)

{
}

ScAgentAction::~ScAgentAction()
{
}

sc_result ScAgentAction::Run(ScAddr const & listenAddr, ScAddr const & edgeAddr, ScAddr const & otherAddr)
{
  SC_UNUSED(otherAddr);

  ScAddr const cmdAddr = m_memoryCtx.GetEdgeTarget(edgeAddr);
  if (cmdAddr.IsValid())
  {
    if (m_memoryCtx.HelperCheckEdge(m_cmdClassAddr, cmdAddr, ScType::EdgeAccessConstPosPerm))
    {
      m_memoryCtx.EraseElement(edgeAddr);
      ScAddr progressAddr = m_memoryCtx.CreateEdge(ScType::EdgeAccessConstPosPerm, ScKeynodes::kCommandProgressdAddr, cmdAddr);
      assert(progressAddr.IsValid());
      ScAddr resultAddr = m_memoryCtx.CreateNode(ScType::NodeConstStruct);
      assert(resultAddr.IsValid());

      sc_result const resCode = RunImpl(cmdAddr, resultAddr);

      m_memoryCtx.EraseElement(progressAddr);

      ScAddr const commonEdge = m_memoryCtx.CreateEdge(ScType::EdgeDCommonConst, cmdAddr, resultAddr);

      m_memoryCtx.CreateEdge(ScType::EdgeAccessConstPosPerm, ScKeynodes::kNrelResult, commonEdge);
      m_memoryCtx.CreateEdge(ScType::EdgeAccessConstPosPerm, ScKeynodes::GetResultCodeAddr(resCode), resultAddr);
      m_memoryCtx.CreateEdge(ScType::EdgeAccessConstPosPerm, ScKeynodes::kCommandFinishedAddr, cmdAddr);

      return SC_RESULT_OK;
    }
  }

  return SC_RESULT_ERROR;
}

ScAddr ScAgentAction::GetParam(ScAddr const & cmdAddr, ScAddr const & relationAddr, ScType const & paramType) const
{
  ScIterator5Ptr iter = m_memoryCtx.Iterator5(cmdAddr,
                                              ScType::EdgeAccessConstPosPerm,
                                              paramType,
                                              ScType::EdgeAccessConstPosPerm,
                                              relationAddr);

  if (!iter->Next())
    return ScAddr();

  return iter->Get(2);
}

ScAddr ScAgentAction::GetParam(ScAddr const & cmdAddr, size_t index) const
{
  return GetParam(cmdAddr, ScKeynodes::GetRrelIndex(index), ScType());
}

ScAddr const & ScAgentAction::GetCommandInitiatedAddr()
{
  return ScKeynodes::kCommandInitiatedAddr;
}

ScAddr const & ScAgentAction::GetCommandFinishedAddr()
{
  return ScKeynodes::kCommandFinishedAddr;
}

ScAddr const & ScAgentAction::GetNrelResultAddr()
{
  return ScKeynodes::kNrelResult;
}

ScAddr ScAgentAction::CreateCommand(ScMemoryContext & ctx, ScAddr const & cmdClassAddr, ScAddrVector const & params)
{
  if (params.size() >= ScKeynodes::GetRrelIndexNum())
    SC_THROW_EXCEPTION(utils::ExceptionInvalidParams, "You should use <= " + std::to_string(ScKeynodes::GetRrelIndexNum()) + " params");

  SC_ASSERT(cmdClassAddr.IsValid(), ());

  ScAddr const cmdInstanceAddr = ctx.CreateNode(ScType::NodeConst);
  SC_ASSERT(cmdInstanceAddr.IsValid(), ());
  ctx.CreateEdge(ScType::EdgeAccessConstPosPerm, cmdClassAddr, cmdInstanceAddr);
  
  for (size_t i = 0; i < params.size(); ++i)
  {
    ScAddr const edgeCommon = ctx.CreateEdge(ScType::EdgeAccessConstPosPerm, cmdInstanceAddr, params[i]);
    SC_ASSERT(edgeCommon.IsValid(), ());
    ctx.CreateEdge(ScType::EdgeAccessConstPosPerm, ScKeynodes::GetRrelIndex(i), edgeCommon);
  }

  return cmdInstanceAddr;
}

bool ScAgentAction::InitiateCommand(ScMemoryContext & ctx, ScAddr const & cmdAddr)
{
  // TODO: add blocks (locks) to prevent adding command to initiated set twicely

  // check if command is in progress
  if (ctx.HelperCheckEdge(ScKeynodes::kCommandProgressdAddr, cmdAddr, ScType::EdgeAccessConstPosPerm))
    return false;

  if (ctx.HelperCheckEdge(ScKeynodes::kCommandInitiatedAddr, cmdAddr, ScType::EdgeAccessConstPosPerm))
    return false;

  return ctx.CreateEdge(ScType::EdgeAccessConstPosPerm, ScKeynodes::kCommandInitiatedAddr, cmdAddr).IsValid();
}

ScAddr ScAgentAction::GetCommandResultAddr(ScMemoryContext & ctx, ScAddr const & cmdAddr)
{
  ScIterator5Ptr it = ctx.Iterator5(
    cmdAddr,
    ScType::EdgeDCommonConst,
    ScType::NodeConstStruct,
    ScType::EdgeAccessConstPosPerm,
    ScKeynodes::kNrelResult);

  if (it->Next())
    return it->Get(2);

  return ScAddr();
}

sc_result ScAgentAction::GetCommandResultCode(ScMemoryContext & ctx, ScAddr const & cmdAddr)
{
  ScAddr const resultAddr = GetCommandResultAddr(ctx, cmdAddr);
  if (!resultAddr.IsValid())
    return SC_RESULT_UNKNOWN;

  ScTemplate templ;
  templ.Triple(
    ScKeynodes::kScResult,
    ScType::EdgeAccessVarPosPerm,
    ScType::NodeVarClass >> "result_class");
  templ.Triple(
    "result_class",
    ScType::EdgeAccessVarPosPerm,
    resultAddr);

  ScTemplateSearchResult searchResult;
  if (!ctx.HelperSearchTemplate(templ, searchResult))
    return SC_RESULT_UNKNOWN;

  SC_ASSERT(searchResult.Size() == 1, ());
  return ScKeynodes::GetResultCodeByAddr(searchResult[0][2]);
}
