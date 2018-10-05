// Copyright 2017 The Crashpad Authors. All rights reserved.
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

#ifndef HANDLER_MINIDUMP_TO_UPLOAD_PARAMETERS_H_
#define HANDLER_MINIDUMP_TO_UPLOAD_PARAMETERS_H_

#include <map>
#include <string>
#include <vector>

namespace crashpad {

class ProcessSnapshot;

//! \brief Given a ProcessSnapshot, returns a map of key-value pairs to use as
//!     HTTP form parameters for upload to a Breakpad crash report colleciton
//!     server.
//!
//! The map is built by combining the process simple annotations map with
//! each module’s simple annotations map and annotation objects.
//!
//! In the case of duplicate simple map keys or annotation names, the map will
//! retain the first value found for any key, and will log a warning about
//! discarded values. The precedence rules for annotation names are: the two
//! reserved keys discussed below, process simple annotations, module simple
//! annotations, and module annotation objects.
//!
//! For annotation objects, only ones of that are Annotation::Type::kString are
//! included.
//!
//! Each module’s annotations vector is also examined and built into a single
//! string value, with distinct elements separated by newlines, and stored at
//! the key named “list_annotations”, which supersedes any other key found by
//! that name.
//!
//! The client ID stored in the minidump is converted to a string and stored at
//! the key named “guid”, which supersedes any other key found by that name.
//!
//! In the event of an error reading the minidump file, a message will be
//! logged.
//!
//! \param[in] process_snapshot The process snapshot from which annotations
//!     will be extracted.
//!
//! \returns A string map of the annotations.
std::map<std::string, std::string> BreakpadHTTPFormParametersFromMinidump(
    const ProcessSnapshot* process_snapshot);

//! \brief Get the configured size limit of uploading a single file.
//!     
//! \returns the maximum number of bytes allowed to upload for a single
//!          attachment, default to \a default_kbytes * 1000, 0 means
//!          unlimited.
int64_t CrashpadUploadAttachmentFileSizeLimit(int default_kbytes = 0);

//! \brief Get the configured percentage of minidump file uploading.
//!     
//! \returns the configured percentage of dump files shall be uploaded to
//!          servers, if none configured, default to \a default_percentage.
int CrashpadUploadPercentage(int default_percentage = 10);

//! \brief whether the configured uploading file format is "minidump"
bool CrashpadUploadMiniDump();

//! \brief Form paramter array suitable for execv the backtrace ptrace tool.
//!
//! \parma[in]  tracer_pathname  The pathname of the tracer executable.
//! \param[in,out] args  The string vector that holds the content.
//! \param[out] argv  The result array of c strings for calling exec*. 
//! \parma[in]  tracee  The ID of the process to be traced.
//! \returns true on sucess
bool MakeAdditionalTracerParameter(
  std::string& tracer_pathname, std::vector<std::string>& args,
  std::vector<const char*>& argv, pid_t tracee, const std::string& outfile);
}  // namespace crashpad

#endif  // HANDLER_MINIDUMP_TO_UPLOAD_PARAMETERS_H_
