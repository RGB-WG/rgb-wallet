// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use amplify::confinement::{Confined, TinyOrdMap, TinyOrdSet};
use rgb::{
    AssignmentType, ExtensionType, GlobalStateType, Occurrences, OpFullType, OpSchema, Schema,
    TransitionType, ValencyType,
};
use strict_encoding::{FieldName, TypeName};

use crate::interface::{
    ExtensionIface, GenesisIface, Iface, IfaceImpl, Modifier, OpName, TransitionIface,
};

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(doc_comments)]
pub enum InheritanceFailure {
    /// invalid schema - no match with root schema requirements for global state
    /// type #{0}.
    GlobalStateMismatch(GlobalStateType),
    /// invalid schema - no match with root schema requirements for assignment
    /// type #{0}.
    AssignmentTypeMismatch(AssignmentType),
    /// invalid schema - no match with root schema requirements for valency
    /// type #{0}.
    ValencyTypeMismatch(ValencyType),
    /// invalid schema - no match with root schema requirements for transition
    /// type #{0}.
    TransitionTypeMismatch(TransitionType),
    /// invalid schema - no match with root schema requirements for extension
    /// type #{0}.
    ExtensionTypeMismatch(ExtensionType),

    /// invalid schema - no match with root schema requirements for global state
    /// type #{1} used in {0}.
    OpGlobalStateMismatch(OpFullType, GlobalStateType),
    /// invalid schema - no match with root schema requirements for input
    /// type #{1} used in {0}.
    OpInputMismatch(OpFullType, AssignmentType),
    /// invalid schema - no match with root schema requirements for redeem
    /// type #{1} used in {0}.
    OpRedeemMismatch(OpFullType, ValencyType),
    /// invalid schema - no match with root schema requirements for assignment
    /// type #{1} used in {0}.
    OpAssignmentsMismatch(OpFullType, AssignmentType),
    /// invalid schema - no match with root schema requirements for valency
    /// type #{1} used in {0}.
    OpValencyMismatch(OpFullType, ValencyType),
}

pub trait CheckInheritance {
    fn check_inheritance(&self, root: &Self) -> Result<(), Vec<InheritanceFailure>>;
}

impl CheckInheritance for Schema {
    fn check_inheritance(&self, root: &Schema) -> Result<(), Vec<InheritanceFailure>> {
        let mut status = vec![];

        for (global_type, data_format) in &self.global_types {
            match root.global_types.get(global_type) {
                None => status.push(InheritanceFailure::GlobalStateMismatch(*global_type)),
                Some(root_data_format) if root_data_format != data_format => {
                    status.push(InheritanceFailure::GlobalStateMismatch(*global_type))
                }
                _ => {}
            };
        }

        for (assignments_type, state_schema) in &self.owned_types {
            match root.owned_types.get(assignments_type) {
                None => status.push(InheritanceFailure::AssignmentTypeMismatch(*assignments_type)),
                Some(root_state_schema) if root_state_schema != state_schema => {
                    status.push(InheritanceFailure::AssignmentTypeMismatch(*assignments_type))
                }
                _ => {}
            };
        }

        for valencies_type in &self.valency_types {
            if !root.valency_types.contains(valencies_type) {
                status.push(InheritanceFailure::ValencyTypeMismatch(*valencies_type));
            }
        }

        self.genesis
            .check_schema_op_inheritance(OpFullType::Genesis, &root.genesis)
            .map_err(|e| status.extend(e))
            .ok();

        for (type_id, transition_schema) in &self.transitions {
            if let Some(root_transition_schema) = root.transitions.get(type_id) {
                transition_schema
                    .check_schema_op_inheritance(
                        OpFullType::StateTransition(*type_id),
                        root_transition_schema,
                    )
                    .map_err(|e| status.extend(e))
                    .ok();
            } else {
                status.push(InheritanceFailure::TransitionTypeMismatch(*type_id));
            }
        }
        for (type_id, extension_schema) in &self.extensions {
            if let Some(root_extension_schema) = root.extensions.get(type_id) {
                extension_schema
                    .check_schema_op_inheritance(
                        OpFullType::StateExtension(*type_id),
                        root_extension_schema,
                    )
                    .map_err(|e| status.extend(e))
                    .ok();
            } else {
                status.push(InheritanceFailure::ExtensionTypeMismatch(*type_id));
            }
        }

        if status.is_empty() {
            Ok(())
        } else {
            Err(status)
        }
    }
}

/// Trait used for internal schema validation against some root schema
pub(crate) trait CheckSchemaOpInheritance {
    fn check_schema_op_inheritance(
        &self,
        op_type: OpFullType,
        root: &Self,
    ) -> Result<(), Vec<InheritanceFailure>>;
}

impl<T> CheckSchemaOpInheritance for T
where T: OpSchema
{
    fn check_schema_op_inheritance(
        &self,
        op_type: OpFullType,
        root: &Self,
    ) -> Result<(), Vec<InheritanceFailure>> {
        let mut status = vec![];

        for (type_id, occ) in self.globals() {
            match root.globals().get(type_id) {
                None => status.push(InheritanceFailure::OpGlobalStateMismatch(op_type, *type_id)),
                Some(root_occ) if occ != root_occ => {
                    status.push(InheritanceFailure::OpGlobalStateMismatch(op_type, *type_id))
                }
                _ => {}
            };
        }

        if let Some(inputs) = self.inputs() {
            let root_inputs = root.inputs().expect("generic guarantees");
            for (type_id, occ) in inputs {
                match root_inputs.get(type_id) {
                    None => status.push(InheritanceFailure::OpInputMismatch(op_type, *type_id)),
                    Some(root_occ) if occ != root_occ => {
                        status.push(InheritanceFailure::OpInputMismatch(op_type, *type_id))
                    }
                    _ => {}
                };
            }
        }

        for (type_id, occ) in self.assignments() {
            match root.assignments().get(type_id) {
                None => status.push(InheritanceFailure::OpAssignmentsMismatch(op_type, *type_id)),
                Some(root_occ) if occ != root_occ => {
                    status.push(InheritanceFailure::OpAssignmentsMismatch(op_type, *type_id))
                }
                _ => {}
            };
        }

        if let Some(redeems) = self.redeems() {
            let root_redeems = root.redeems().expect("generic guarantees");
            for type_id in redeems {
                if !root_redeems.contains(type_id) {
                    status.push(InheritanceFailure::OpRedeemMismatch(op_type, *type_id));
                }
            }
        }

        for type_id in self.valencies() {
            if !root.valencies().contains(type_id) {
                status.push(InheritanceFailure::OpValencyMismatch(op_type, *type_id));
            }
        }

        if status.is_empty() {
            Ok(())
        } else {
            Err(status)
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("{iface} {err}")]
pub struct InheritError {
    err: ExtensionError,
    iface: TypeName,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ExtensionError {
    /// too many metadata fields defined.
    MetaOverflow,
    /// too many global state types defined.
    GlobalOverflow,
    /// global state '{0}' has different data type from the parent interface.
    GlobalType(FieldName),
    /// global state '{0}' has fewer occurrences than in the parent interface.
    GlobalOcc(FieldName),
    /// too many assignment types defined.
    AssignmentOverflow,
    /// assignment '{0}' has different data type from the parent interface.
    AssignmentType(FieldName),
    /// assignment '{0}' has fewer occurrences than in the parent interface.
    AssignmentOcc(FieldName),
    /// global state '{0}' has lower visibility than in the parent interface.
    AssignmentPublic(FieldName),
    /// too many valency types defined.
    ValencyOverflow,
    /// valency '{0}' has fewer occurrences than in the parent interface.
    ValencyOcc(FieldName),
    /// too many state transitions.
    TransitionOverflow,
    /// too many state extensions.
    ExtensionOverflow,
    /// too many error types defined.
    ErrorOverflow,
    /// inherited interface tries to override the parent default operation.
    DefaultOverride,
    /// {0} in the parent interface is final and can't be overridden.
    OpFinal(OpName),
    /// {0} must use `override` keyword to modify the parent version.
    OpNoOverride(OpName),
    /// too many {1} types defined in {0}.
    OpOverflow(OpName, &'static str),
    /// {0} tries to override the parent default assignment.
    OpDefaultOverride(OpName),
    /// {0} tries to override '{2}' {1}.
    OpOcc(OpName, &'static str, FieldName),
    /// too deep inheritance; it is not allowed for any interface to have more
    /// than 255 parents it inherits from, including all grandparents.
    InheritanceOverflow,
}

impl Modifier {
    pub fn is_final(self) -> bool { self == Self::Final }
    pub fn can_be_overridden_by(self, other: Modifier) -> bool {
        matches!((self, other), (Self::Abstract | Self::Override, Self::Override | Self::Final))
    }
}

impl Iface {
    pub fn expect_inherit(
        name: impl Into<TypeName>,
        ifaces: impl IntoIterator<Item = Iface>,
    ) -> Iface {
        let name = name.into();
        match Self::inherit(name.clone(), ifaces) {
            Ok(iface) => iface,
            Err(msgs) => {
                eprintln!("Unable to construct interface {name}:");
                for msg in msgs {
                    eprintln!("- {msg}")
                }
                panic!();
            }
        }
    }

    pub fn inherit(
        name: impl Into<TypeName>,
        ifaces: impl IntoIterator<Item = Iface>,
    ) -> Result<Iface, Vec<InheritError>> {
        let name = name.into();
        let mut iter = ifaces.into_iter();
        let mut iface = iter
            .next()
            .expect("at least one interface must be provided for the inheritance");
        for ext in iter {
            let ext_name = ext.name.clone();
            iface = iface.extended(ext, name.clone()).map_err(|err| {
                err.into_iter()
                    .map(|e| InheritError {
                        err: e,
                        iface: ext_name.clone(),
                    })
                    .collect::<Vec<_>>()
            })?;
        }
        Ok(iface)
    }

    pub fn expect_extended(self, ext: Iface, name: impl Into<TypeName>) -> Iface {
        let prev_name = self.name.clone();
        let ext_name = ext.name.clone();
        match self.extended(ext, name) {
            Ok(iface) => iface,
            Err(msgs) => {
                eprintln!("Unable to extend {prev_name} with {ext_name}:");
                for msg in msgs {
                    eprintln!("- {msg}")
                }
                panic!();
            }
        }
    }

    pub fn extended(
        mut self,
        ext: Iface,
        name: impl Into<TypeName>,
    ) -> Result<Iface, Vec<ExtensionError>> {
        let orig_id = self.iface_id();
        let ext_id = ext.iface_id();
        let name = name.into();

        let mut errors = vec![];

        self.metadata
            .extend(ext.metadata)
            .map_err(|_| errors.push(ExtensionError::MetaOverflow))
            .ok();

        for (name, e) in ext.global_state {
            match self.global_state.get_mut(&name) {
                None => {
                    if self
                        .global_state
                        .insert(name, e)
                        .map_err(|_| errors.push(ExtensionError::GlobalOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Some(orig) => {
                    if orig.sem_id.is_some() && e.sem_id != orig.sem_id {
                        errors.push(ExtensionError::GlobalType(name));
                    } else if orig.required & !e.required {
                        errors.push(ExtensionError::GlobalOcc(name));
                    } else {
                        *orig = e;
                    }
                }
            }
        }

        for (name, e) in ext.assignments {
            match self.assignments.get_mut(&name) {
                None => {
                    if self
                        .assignments
                        .insert(name, e)
                        .map_err(|_| errors.push(ExtensionError::AssignmentOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Some(orig) => {
                    if orig.state_ty.is_some() && orig.state_ty != e.state_ty {
                        errors.push(ExtensionError::AssignmentType(name));
                    } else if orig.required & !e.required {
                        errors.push(ExtensionError::AssignmentOcc(name));
                    } else if orig.public & !e.public {
                        errors.push(ExtensionError::AssignmentPublic(name));
                    } else {
                        *orig = e;
                    }
                }
            }
        }

        for (name, e) in ext.valencies {
            match self.valencies.get_mut(&name) {
                None => {
                    if self
                        .valencies
                        .insert(name, e)
                        .map_err(|_| errors.push(ExtensionError::ValencyOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Some(orig) => {
                    if orig.required & !e.required {
                        errors.push(ExtensionError::ValencyOcc(name));
                    } else {
                        *orig = e;
                    }
                }
            }
        }

        self.clone()
            .genesis
            .extended(ext.genesis)
            .map(|genesis| self.genesis = genesis)
            .map_err(|errs| errors.extend(errs))
            .ok();

        for (name, op) in ext.transitions {
            match self.transitions.remove(&name) {
                Ok(None) if op.optional => continue,
                Ok(None) => {
                    if self
                        .transitions
                        .insert(name, op)
                        .map_err(|_| errors.push(ExtensionError::TransitionOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Some(orig)) => {
                    orig.extended(op, name.clone())
                        .map(|op| self.transitions.insert(name, op).expect("same size"))
                        .map_err(|errs| errors.extend(errs))
                        .ok();
                }
                Err(_) => unreachable!(),
            }
        }

        for (name, op) in ext.extensions {
            match self.extensions.remove(&name) {
                Ok(None) if op.optional => continue,
                Ok(None) => {
                    if self
                        .extensions
                        .insert(name, op)
                        .map_err(|_| errors.push(ExtensionError::TransitionOverflow))
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Some(orig)) => {
                    orig.extended(op, name.clone())
                        .map(|op| self.extensions.insert(name, op).expect("same size"))
                        .map_err(|errs| errors.extend(errs))
                        .ok();
                }
                Err(_) => unreachable!(),
            }
        }

        // We allow replacing error messages
        self.errors
            .extend(ext.errors)
            .map_err(|_| errors.push(ExtensionError::ErrorOverflow))
            .ok();

        if ext.default_operation.is_some() {
            if self.default_operation.is_some() && self.default_operation != ext.default_operation {
                errors.push(ExtensionError::DefaultOverride);
            } else {
                self.default_operation = ext.default_operation
            }
        }

        self.name = name;
        self.inherits
            .push(orig_id)
            .and_then(|_| self.inherits.extend(ext.inherits))
            .and_then(|_| self.inherits.push(ext_id))
            .map_err(|_| errors.push(ExtensionError::InheritanceOverflow))
            .ok();

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}

fn check_occs(
    orig: &mut TinyOrdMap<FieldName, Occurrences>,
    ext: impl IntoIterator<Item = (FieldName, Occurrences)>,
    op: OpName,
    state: &'static str,
    errors: &mut Vec<ExtensionError>,
) {
    for (name, occ) in ext {
        match orig.get_mut(&name) {
            None => {
                if orig
                    .insert(name, occ)
                    .map_err(|_| errors.push(ExtensionError::OpOverflow(op.clone(), state)))
                    .is_err()
                {
                    break;
                }
            }
            Some(orig) => {
                if orig.min_value() > occ.min_value() {
                    errors.push(ExtensionError::OpOcc(op.clone(), state, name));
                } else {
                    *orig = occ;
                }
            }
        }
    }
}

fn check_presence<T: Ord + ToString>(
    orig: &mut TinyOrdSet<T>,
    ext: impl IntoIterator<Item = T>,
    op: OpName,
    state: &'static str,
    errors: &mut Vec<ExtensionError>,
) {
    for name in ext {
        if orig
            .push(name)
            .map_err(|_| errors.push(ExtensionError::OpOverflow(op.clone(), state)))
            .is_err()
        {
            break;
        }
    }
}

impl GenesisIface {
    pub fn extended(mut self, ext: Self) -> Result<Self, Vec<ExtensionError>> {
        let mut errors = vec![];

        let op = OpName::Genesis;
        if self.modifier.is_final() {
            errors.push(ExtensionError::OpFinal(op.clone()));
        } else if !self.modifier.can_be_overridden_by(ext.modifier) {
            errors.push(ExtensionError::OpNoOverride(op.clone()));
        }

        self.metadata
            .extend(ext.metadata)
            .map_err(|_| errors.push(ExtensionError::OpOverflow(OpName::Genesis, "metadata")))
            .ok();
        check_occs(&mut self.globals, ext.globals, op.clone(), "global", &mut errors);
        check_occs(&mut self.assignments, ext.assignments, op.clone(), "assignment", &mut errors);

        check_presence(&mut self.valencies, ext.valencies, op.clone(), "valency", &mut errors);
        check_presence(&mut self.errors, ext.errors, op.clone(), "error", &mut errors);

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}

impl TransitionIface {
    pub fn extended(mut self, ext: Self, op_name: FieldName) -> Result<Self, Vec<ExtensionError>> {
        let mut errors = vec![];

        let op = OpName::Transition(op_name);
        if self.modifier.is_final() {
            errors.push(ExtensionError::OpFinal(op.clone()));
        } else if !self.modifier.can_be_overridden_by(ext.modifier) {
            errors.push(ExtensionError::OpNoOverride(op.clone()));
        }
        self.optional = self.optional.max(ext.optional);

        self.metadata
            .extend(ext.metadata)
            .map_err(|_| errors.push(ExtensionError::OpOverflow(op.clone(), "metadata")))
            .ok();
        check_occs(&mut self.globals, ext.globals, op.clone(), "global", &mut errors);
        check_occs(&mut self.assignments, ext.assignments, op.clone(), "assignment", &mut errors);
        check_occs(&mut self.inputs, ext.inputs, op.clone(), "input", &mut errors);

        check_presence(&mut self.valencies, ext.valencies, op.clone(), "valency", &mut errors);
        check_presence(&mut self.errors, ext.errors, op.clone(), "error", &mut errors);

        if ext.default_assignment.is_some() {
            if self.default_assignment.is_some()
                && self.default_assignment != ext.default_assignment
            {
                errors.push(ExtensionError::OpDefaultOverride(op.clone()));
            } else {
                self.default_assignment = ext.default_assignment
            }
        }

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}

impl ExtensionIface {
    pub fn extended(mut self, ext: Self, op_name: FieldName) -> Result<Self, Vec<ExtensionError>> {
        let mut errors = vec![];

        let op = OpName::Transition(op_name);
        if self.modifier.is_final() {
            errors.push(ExtensionError::OpFinal(op.clone()));
        } else if !self.modifier.can_be_overridden_by(ext.modifier) {
            errors.push(ExtensionError::OpNoOverride(op.clone()));
        }
        self.optional = self.optional.max(ext.optional);

        self.metadata
            .extend(ext.metadata)
            .map_err(|_| errors.push(ExtensionError::OpOverflow(op.clone(), "metadata")))
            .ok();
        check_occs(&mut self.globals, ext.globals, op.clone(), "global", &mut errors);
        check_occs(&mut self.assignments, ext.assignments, op.clone(), "assignment", &mut errors);

        check_presence(&mut self.valencies, ext.valencies, op.clone(), "valency", &mut errors);
        check_presence(&mut self.redeems, ext.redeems, op.clone(), "input", &mut errors);
        check_presence(&mut self.errors, ext.errors, op.clone(), "error", &mut errors);

        if ext.default_assignment.is_some() {
            if self.default_assignment.is_some()
                && self.default_assignment != ext.default_assignment
            {
                errors.push(ExtensionError::OpDefaultOverride(op.clone()));
            } else {
                self.default_assignment = ext.default_assignment
            }
        }

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}

impl IfaceImpl {
    pub fn abstracted(mut self, base: &Iface, parent: &Iface) -> Option<Self> {
        assert_eq!(self.iface_id, base.iface_id());
        let parent_id = parent.iface_id();
        if !base.inherits.contains(&parent_id) {
            return None;
        }

        self.metadata = Confined::from_iter_checked(base.metadata.keys().filter_map(|name| {
            self.metadata
                .iter()
                .find(|i| parent.metadata.contains_key(name) && &i.name == name)
                .cloned()
        }));

        self.global_state =
            Confined::from_iter_checked(base.global_state.keys().filter_map(|name| {
                self.global_state
                    .iter()
                    .find(|i| parent.global_state.contains_key(name) && &i.name == name)
                    .cloned()
            }));

        self.assignments =
            Confined::from_iter_checked(base.assignments.keys().filter_map(|name| {
                self.assignments
                    .iter()
                    .find(|i| parent.assignments.contains_key(name) && &i.name == name)
                    .cloned()
            }));

        self.valencies = Confined::from_iter_checked(base.assignments.keys().filter_map(|name| {
            self.valencies
                .iter()
                .find(|i| parent.valencies.contains_key(name) && &i.name == name)
                .cloned()
        }));

        self.transitions =
            Confined::from_iter_checked(base.transitions.keys().filter_map(|name| {
                self.transitions
                    .iter()
                    .find(|i| parent.transitions.contains_key(name) && &i.name == name)
                    .cloned()
            }));

        self.extensions = Confined::from_iter_checked(base.extensions.keys().filter_map(|name| {
            self.extensions
                .iter()
                .find(|i| parent.extensions.contains_key(name) && &i.name == name)
                .cloned()
        }));

        self.iface_id = parent_id;

        Some(self)
    }
}
