// Anti-Google — removes Google telemetry from Windows, and tells you what that breaks first.
// Copyright (C) 2026 The Anti-Google contributors
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using AntiGoogle.Core.Journal;

namespace AntiGoogle.Core.Engines;

/// <summary>
/// Contract every engine honours: journal the reverse BEFORE mutating, and be able to undo
/// any entry it produced without needing the original rule definition to still exist.
/// </summary>
public interface IRevertEngine
{
    Model.EngineKind Kind { get; }

    /// <summary>Undo exactly one journalled change. Must be idempotent — reverting twice is not an error.</summary>
    Task RevertAsync(JournalEntry entry, CancellationToken ct = default);
}
