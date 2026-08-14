import Lean
import Lean.CoreM
import Lean.Meta.Basic
import Lean.Util.CollectAxioms
import Lean.Util.Path

open Lean

private def nameFromString (value : String) : Name :=
  value.splitOn "." |>.foldl (fun name part => Name.str name part) .anonymous

private def fail (message : String) : IO UInt32 := do
  IO.eprintln message
  return 1

private def verify (args : List String) : IO UInt32 := do
  let [targetModuleText, targetDeclText, entryModuleText, entryDeclText, permittedText] := args
    | return ← fail "NumOJ Lean verifier received invalid arguments"
  let targetModule := nameFromString targetModuleText
  let targetDecl := nameFromString targetDeclText
  let entryModule := nameFromString entryModuleText
  let entryDecl := nameFromString entryDeclText
  let permitted := (permittedText.splitOn ",").filter (· != "") |>.map nameFromString
  let imports : Array Import := #[{ module := targetModule }, { module := entryModule }]
  let env ← importModules imports {} (trustLevel := 0) (loadExts := false)

  let some targetInfo := env.find? targetDecl
    | return ← fail s!"Target declaration not found: {targetDecl}"
  let targetOrigin :=
    (env.header.moduleNames[·]!) <$> env.getModuleIdxFor? targetDecl
  if targetOrigin != some targetModule then
    return ← fail "Target declaration must come from the readonly target module"
  let targetValue ← match targetInfo with
    | .defnInfo value => pure value
    | _ => return ← fail "Target declaration must be a safe def"
  if targetValue.safety != .safe || !targetValue.levelParams.isEmpty then
    return ← fail "Target declaration must be a monomorphic safe def"
  if targetValue.type != mkSort .zero then
    return ← fail "Target declaration must have type Prop"

  let some entryInfo := env.find? entryDecl
    | return ← fail s!"Proof declaration not found: {entryDecl}"
  let entryOrigin :=
    (env.header.moduleNames[·]!) <$> env.getModuleIdxFor? entryDecl
  if entryOrigin != some entryModule then
    return ← fail "Proof entry must come from the writable entry module"
  let entryValue ← match entryInfo with
    | .thmInfo value => pure value
    | _ => return ← fail "Proof entry must be a theorem"
  if !entryValue.levelParams.isEmpty then
    return ← fail "Proof entry must be monomorphic"
  let coreContext : Core.Context := {
    fileName := "<numoj-verifier>"
    fileMap := FileMap.ofString ""
  }
  let (typesMatch, _, _) ← Lean.Meta.MetaM.toIO
    (Meta.isDefEq entryValue.type (mkConst targetDecl))
    coreContext
    { env := env }
  if !typesMatch then
    return ← fail s!"Proof entry must have type {targetDecl}"

  let axioms ← Lean.Core.CoreM.toIO'
    (collectAxioms entryDecl) coreContext { env := env }
  let forbidden := axioms.filter fun name => !permitted.contains name
  if !forbidden.isEmpty then
    return ← fail s!"Proof uses forbidden axioms: {String.intercalate ", " (forbidden.toList.map toString)}"

  IO.println "__NUMOJ_VERIFIER_RESULT_BEGIN__"
  for axiomName in axioms do
    IO.println s!"AXIOM={axiomName}"
  IO.println "RESULT=ACCEPTED"
  return 0

def main (args : List String) : IO UInt32 := do
  try
    initSearchPath (← findSysroot)
    verify args
  catch error => fail s!"Lean verifier failed: {error}"
