# type: ignore
# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: api_options.proto
# Protobuf Python Version: 6.30.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    6,
    30,
    0,
    '',
    'api_options.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import descriptor_pb2 as google_dot_protobuf_dot_descriptor__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x11\x61pi_options.proto\x1a google/protobuf/descriptor.proto\"\x06\n\x04void*F\n\rAPISourceType\x12\x0f\n\x0bSOURCE_BOTH\x10\x00\x12\x11\n\rSOURCE_SERVER\x10\x01\x12\x11\n\rSOURCE_CLIENT\x10\x02:E\n\x16needs_setup_connection\x12\x1e.google.protobuf.MethodOptions\x18\x8e\x08 \x01(\x08:\x04true:C\n\x14needs_authentication\x12\x1e.google.protobuf.MethodOptions\x18\x8f\x08 \x01(\x08:\x04true:/\n\x02id\x12\x1f.google.protobuf.MessageOptions\x18\x8c\x08 \x01(\r:\x01\x30:M\n\x06source\x12\x1f.google.protobuf.MessageOptions\x18\x8d\x08 \x01(\x0e\x32\x0e.APISourceType:\x0bSOURCE_BOTH:/\n\x05ifdef\x12\x1f.google.protobuf.MessageOptions\x18\x8e\x08 \x01(\t:3\n\x03log\x12\x1f.google.protobuf.MessageOptions\x18\x8f\x08 \x01(\x08:\x04true:9\n\x08no_delay\x12\x1f.google.protobuf.MessageOptions\x18\x90\x08 \x01(\x08:\x05\x66\x61lse:4\n\nbase_class\x12\x1f.google.protobuf.MessageOptions\x18\x91\x08 \x01(\t:3\n\x0b\x66ield_ifdef\x12\x1d.google.protobuf.FieldOptions\x18\x92\x08 \x01(\t:9\n\x10\x66ixed_array_size\x12\x1d.google.protobuf.FieldOptions\x18\xd7\x86\x03 \x01(\r:<\n\x0cno_zero_copy\x12\x1d.google.protobuf.FieldOptions\x18\xd8\x86\x03 \x01(\x08:\x05\x66\x61lse:E\n\x15\x66ixed_array_skip_zero\x12\x1d.google.protobuf.FieldOptions\x18\xd9\x86\x03 \x01(\x08:\x05\x66\x61lse:@\n\x17\x66ixed_array_size_define\x12\x1d.google.protobuf.FieldOptions\x18\xda\x86\x03 \x01(\t::\n\x11\x63ontainer_pointer\x12\x1d.google.protobuf.FieldOptions\x18\xd1\x86\x03 \x01(\t')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'api_options_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_APISOURCETYPE']._serialized_start=63
  _globals['_APISOURCETYPE']._serialized_end=133
  _globals['_VOID']._serialized_start=55
  _globals['_VOID']._serialized_end=61
# @@protoc_insertion_point(module_scope)
