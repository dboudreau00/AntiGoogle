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
namespace AntiGoogle.Core.Model;

/// <summary>
/// How much collateral damage a rule is willing to accept. The shipped default profile is
/// <see cref="Aggressive"/>, which is deliberately loud: see <see cref="Breakage"/>.
/// </summary>
public enum RiskTier
{
    /// <summary>Telemetry and crash-report endpoints only. Effectively zero breakage.</summary>
    Conservative = 0,

    /// <summary>Adds update pings, ad/analytics networks, Chrome background phone-home.</summary>
    Balanced = 1,

    /// <summary>Full Google reach removal. Breaks fonts, captcha, push, Cast, Play, Firebase.</summary>
    Aggressive = 2
}

/// <summary>How badly a real user-facing capability degrades when a rule is armed.</summary>
public enum BreakageSeverity
{
    /// <summary>No observable loss.</summary>
    None = 0,

    /// <summary>Cosmetic or rarely noticed. A fallback exists.</summary>
    Minor = 1,

    /// <summary>A feature visibly stops working, but the app still runs.</summary>
    Notable = 2,

    /// <summary>Something the user relies on will fail outright, possibly locking them out.</summary>
    Severe = 3
}

/// <summary>Which subsystem actually carries out a rule. Each has its own revert path.</summary>
public enum EngineKind
{
    Hosts = 0,
    Firewall = 1,
    Service = 2,
    ScheduledTask = 3,
    Registry = 4,
    AppContainment = 5
}

/// <summary>Grouping used by the UI only.</summary>
public enum RuleCategory
{
    Telemetry,
    CrashReporting,
    Updates,
    AdsAnalytics,
    ApisCdn,
    AuthCaptcha,
    Push,
    Media,
    Sync,
    Search,
    WindowsIntegration,
    Containment
}

/// <summary>Result of attempting a single planned change.</summary>
public enum ChangeOutcome
{
    /// <summary>Applied, and a reverse entry was journalled.</summary>
    Applied,

    /// <summary>Target was already in the desired state; nothing was written.</summary>
    AlreadySatisfied,

    /// <summary>Target does not exist on this machine (e.g. Chrome never installed).</summary>
    NotPresent,

    /// <summary>Attempted and failed. <see cref="PlannedChange"/> carries the error.</summary>
    Failed,

    /// <summary>Blocked by a preflight safety check and deliberately not attempted.</summary>
    Refused
}
