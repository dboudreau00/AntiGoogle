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

using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Model;
using Xunit;

namespace AntiGoogle.Core.Tests;

/// <summary>
/// Guards the properties of the catalog that users' machines depend on. A rule that is armed by
/// default but does not declare what it breaks defeats the entire point of the app, so that is a
/// test failure rather than an editorial preference.
/// </summary>
public class CatalogTests
{
    [Fact]
    public void RuleIdsAreUnique()
    {
        var dupes = RuleCatalog.All
            .GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        Assert.Empty(dupes);
    }

    [Fact]
    public void EveryRuleHasAPayloadMatchingItsEngine()
    {
        foreach (var rule in RuleCatalog.All)
        {
            var populated = rule.Engine switch
            {
                EngineKind.Hosts => rule.Domains.Count > 0,
                EngineKind.Firewall => rule.IpRanges.Count > 0,
                EngineKind.Registry => rule.RegistryValues.Count > 0,
                EngineKind.Service => rule.ServiceNamePatterns.Count > 0,
                EngineKind.ScheduledTask => rule.ScheduledTaskPatterns.Count > 0,
                _ => true
            };

            Assert.True(populated, $"Rule {rule.Id} declares engine {rule.Engine} but carries no matching payload.");
        }
    }

    [Fact]
    public void ConsentGatedRulesAreNeverArmedByDefault()
    {
        // A rule that can lock the user out of their accounts must not be armed by the shipped
        // profile — the whole reason it is consent-gated is that a click should not be enough.
        foreach (var rule in RuleCatalog.All.Where(r => r.RequiresExplicitConsent))
            Assert.False(rule.DefaultEnabled, $"Consent-gated rule {rule.Id} is enabled by default.");
    }

    [Fact]
    public void EveryDefaultEnabledRuleDeclaresItsBreakage()
    {
        foreach (var rule in RuleCatalog.All.Where(r => r.DefaultEnabled))
            Assert.True(rule.Breaks.Count > 0,
                $"Rule {rule.Id} is armed by default but declares no degradation. " +
                "Either it genuinely breaks nothing (say so explicitly) or the list is incomplete.");
    }

    [Fact]
    public void EverySevereBreakageHasAnActionableDetail()
    {
        foreach (var rule in RuleCatalog.All)
        foreach (var b in rule.Breaks.Where(b => b.Severity == BreakageSeverity.Severe))
        {
            Assert.False(string.IsNullOrWhiteSpace(b.Detail));
            Assert.True(b.Detail.Length > 40,
                $"{rule.Id}: severe breakage '{b.What}' needs a real explanation, not a stub.");
        }
    }

    [Fact]
    public void SafeBrowsingIsOffByDefault()
    {
        // Deliberate product decision: disabling phishing/malware protection is a security
        // regression the user must opt into, even on the Aggressive profile.
        foreach (var id in new[] { "hosts.safebrowsing", "reg.chrome.safebrowsing" })
            Assert.False(RuleCatalog.ById(id)!.DefaultEnabled, $"{id} must stay off by default.");
    }

    [Fact]
    public void DomainsAreLowercaseAndHaveNoScheme()
    {
        foreach (var rule in RuleCatalog.All)
        foreach (var d in rule.Domains)
        {
            Assert.Equal(d.ToLowerInvariant(), d);
            Assert.DoesNotContain("/", d);
            Assert.DoesNotContain(":", d);
        }
    }

    [Fact]
    public void GoogleDnsIsNotInTheCoreFirewallRanges()
    {
        // 8.8.8.8 must only ever be reachable through the dedicated, preflight-guarded rule.
        // If it leaked into the core range list, arming the general block could kill DNS.
        Assert.DoesNotContain(GoogleIpRanges.Core, r => r.StartsWith("8.8.", StringComparison.Ordinal));
    }
}
