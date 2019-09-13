# Copyright 2014 The Crashpad Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

{
  'includes': [
    '../build/crashpad.gypi',
  ],
  'targets': [
    {
      'target_name': 'tool_support',
      'type': 'static_library',
      'standalone_static_library': 1,
      'dependencies': [
        '../third_party/mini_chromium/mini_chromium.gyp:base',
      ],
      'include_dirs': [
        '..',
      ],
      'sources': [
        'tool_support.cc',
        'tool_support.h',
      ],
    },
    {
      'target_name': 'database_util',
      'type': 'executable',
      'dependencies': [
        'tool_support',
        '../client/client.gyp:client',
        '../compat/compat.gyp:compat',
        '../third_party/mini_chromium/mini_chromium.gyp:base',
        '../util/util.gyp:util',
      ],
      'include_dirs': [
        '..',
      ],
      'sources': [
        'crashpad_database_util.cc',
      ],
    },
    {
      'target_name': 'http_upload',
      'type': 'executable',
      'dependencies': [
        'tool_support',
        '../compat/compat.gyp:compat',
        '../third_party/mini_chromium/mini_chromium.gyp:base',
        '../util/util.gyp:util',
      ],
      'include_dirs': [
        '..',
      ],
      'sources': [
        'crashpad_http_upload.cc',
      ],
    },
    {
      'target_name': 'generate_dump',
      'type': 'executable',
      'dependencies': [
        'tool_support',
        '../compat/compat.gyp:compat',
        '../minidump/minidump.gyp:minidump',
        '../snapshot/snapshot.gyp:snapshot',
        '../third_party/mini_chromium/mini_chromium.gyp:base',
        '../util/util.gyp:util',
      ],
      'include_dirs': [
        '..',
      ],
      'sources': [
        'generate_dump.cc',
      ],
      'conditions': [
        ['OS=="mac"', {
          'xcode_settings': {
            'OTHER_LDFLAGS': [
              '-sectcreate',
              '__TEXT',
              '__info_plist',
              '<(sectaskaccess_info_plist)'
            ],
          },
        }],
      ],
    },
  ],
  'conditions': [
    ['OS=="mac"', {
      'variables': {
        # Programs that use task_for_pid() can indicate to taskgated(8) in their
        # Info.plist that they are allowed to call that function. In order for
        # this to work, the programs in question must be signed by an authority
        # trusted by the system. Signing is beyond the scope of the build, but
        # the key to make this work is placed in Info.plist to enable the
        # desired behavior once the tools that require this access are signed.
        #
        # The tools built here are flat-file executables, and are not bundled.
        # To have an Info.plist, they must have a special __TEXT,__info_plist
        # section. This section is created at link time.
        #
        # The Info.plist for this purpose is mac/sectaskaccess_info.plist and is
        # referenced by OTHER_LDFLAGS. ninja runs the link step from the output
        # directory such as out/Release, and requires a relative path from that
        # directory. Xcode runs the link step from the directory of the
        # .xcodeproj, which is the directory of the .gyp file.
        'conditions': [
          ['GENERATOR=="ninja"', {
            'sectaskaccess_info_plist': '<!(pwd)/mac/sectaskaccess_info.plist',
          }, {  # else: GENERATOR!="ninja"
            'sectaskaccess_info_plist': 'mac/sectaskaccess_info.plist',
          }],
        ],
      },

      'targets': [
        {
          'target_name': 'catch_exception_tool',
          'type': 'executable',
          'dependencies': [
            'tool_support',
            '../compat/compat.gyp:compat',
            '../third_party/mini_chromium/mini_chromium.gyp:base',
            '../util/util.gyp:util',
          ],
          'include_dirs': [
            '..',
          ],
          'sources': [
            'mac/catch_exception_tool.cc',
          ],
        },
        {
          'target_name': 'exception_port_tool',
          'type': 'executable',
          'dependencies': [
            'tool_support',
            '../compat/compat.gyp:compat',
            '../third_party/mini_chromium/mini_chromium.gyp:base',
            '../util/util.gyp:util',
          ],
          'include_dirs': [
            '..',
          ],
          'sources': [
            'mac/exception_port_tool.cc',
          ],
          'xcode_settings': {
            'OTHER_LDFLAGS': [
              '-sectcreate',
              '__TEXT',
              '__info_plist',
              '<(sectaskaccess_info_plist)'
            ],
          },
        },
        {
          'target_name': 'on_demand_service_tool',
          'type': 'executable',
          'dependencies': [
            'tool_support',
            '../compat/compat.gyp:compat',
            '../third_party/mini_chromium/mini_chromium.gyp:base',
            '../util/util.gyp:util',
          ],
          'include_dirs': [
            '..',
          ],
          'link_settings': {
            'libraries': [
              '$(SDKROOT)/System/Library/Frameworks/CoreFoundation.framework',
              '$(SDKROOT)/System/Library/Frameworks/Foundation.framework',
            ],
          },
          'sources': [
            'mac/on_demand_service_tool.mm',
          ],
        },
        {
          'target_name': 'run_with_crashpad',
          'type': 'executable',
          'dependencies': [
            'tool_support',
            '../client/client.gyp:client',
            '../compat/compat.gyp:compat',
            '../third_party/mini_chromium/mini_chromium.gyp:base',
            '../util/util.gyp:util',
          ],
          'include_dirs': [
            '..',
          ],
          'sources': [
            'run_with_crashpad.cc',
          ],
        },
      ],
    }],
  ],
}
