// rootlesscontainers-proto: persistent rootless filesystem emulation
// Copyright (C) 2018 Rootless Containers Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.12.4
// source: rootlesscontainers.proto

// The rootlesscontainers package is maintained at https://github.com/rootless-containers/proto .
// If you want to extend the resource definition, please open a PR.

package rootlesscontainers

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Resource defines the schema for "user.rootlesscontainers" xattr values.
// The resource can be used as a persistent storage for emulated `chown(2)` syscall.
// Syscall emulators SHOULD try to hide this xattr from the emulated environment.
type Resource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Zero-value MUST be parsed as a literally zero-value, not "unset".
	// To keep both uid and gid unchaged, the entire xattr value SHOULD be removed.
	// To keep either one of uid or gid unchaged, 0xFFFFFFFF (in other words,
	// `(uint32_t) -1`, see also chown(2)) value SHOULD be set.
	// (Because some protobuf bindings cannot distinguish "unset" from zero-value.)
	Uid uint32 `protobuf:"varint,1,opt,name=uid,proto3" json:"uid,omitempty"`
	Gid uint32 `protobuf:"varint,2,opt,name=gid,proto3" json:"gid,omitempty"`
}

func (x *Resource) Reset() {
	*x = Resource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rootlesscontainers_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Resource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Resource) ProtoMessage() {}

func (x *Resource) ProtoReflect() protoreflect.Message {
	mi := &file_rootlesscontainers_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Resource.ProtoReflect.Descriptor instead.
func (*Resource) Descriptor() ([]byte, []int) {
	return file_rootlesscontainers_proto_rawDescGZIP(), []int{0}
}

func (x *Resource) GetUid() uint32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

func (x *Resource) GetGid() uint32 {
	if x != nil {
		return x.Gid
	}
	return 0
}

var File_rootlesscontainers_proto protoreflect.FileDescriptor

var file_rootlesscontainers_proto_rawDesc = []byte{
	0x0a, 0x18, 0x72, 0x6f, 0x6f, 0x74, 0x6c, 0x65, 0x73, 0x73, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69,
	0x6e, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x12, 0x72, 0x6f, 0x6f, 0x74,
	0x6c, 0x65, 0x73, 0x73, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x22, 0x2e,
	0x0a, 0x08, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03,
	0x67, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x67, 0x69, 0x64, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rootlesscontainers_proto_rawDescOnce sync.Once
	file_rootlesscontainers_proto_rawDescData = file_rootlesscontainers_proto_rawDesc
)

func file_rootlesscontainers_proto_rawDescGZIP() []byte {
	file_rootlesscontainers_proto_rawDescOnce.Do(func() {
		file_rootlesscontainers_proto_rawDescData = protoimpl.X.CompressGZIP(file_rootlesscontainers_proto_rawDescData)
	})
	return file_rootlesscontainers_proto_rawDescData
}

var file_rootlesscontainers_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_rootlesscontainers_proto_goTypes = []interface{}{
	(*Resource)(nil), // 0: rootlesscontainers.Resource
}
var file_rootlesscontainers_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_rootlesscontainers_proto_init() }
func file_rootlesscontainers_proto_init() {
	if File_rootlesscontainers_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rootlesscontainers_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Resource); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_rootlesscontainers_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_rootlesscontainers_proto_goTypes,
		DependencyIndexes: file_rootlesscontainers_proto_depIdxs,
		MessageInfos:      file_rootlesscontainers_proto_msgTypes,
	}.Build()
	File_rootlesscontainers_proto = out.File
	file_rootlesscontainers_proto_rawDesc = nil
	file_rootlesscontainers_proto_goTypes = nil
	file_rootlesscontainers_proto_depIdxs = nil
}
