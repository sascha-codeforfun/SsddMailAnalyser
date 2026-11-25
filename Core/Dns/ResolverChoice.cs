using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace SsddMailAnalyser.Core.Dns;

public enum ResolverKind { Authoritative, Server, Doh }

/// <summary>An entry in the resolver list on the Checks page.</summary>
public sealed class ResolverChoice
{
    public ResolverKind Kind { get; init; }
    public IPAddress? Server { get; init; }
    public string? DohProvider { get; init; }
    public bool IsSystem { get; init; }
    public string Display { get; init; } = "";

    public override string ToString() => Display;

    public IDnsResolver Create() => Kind switch
    {
        ResolverKind.Authoritative => new IterativeResolver(),
        ResolverKind.Doh => DohProvider switch
        {
            "Google" => DohResolver.Google(),
            "Quad9" => DohResolver.Quad9(),
            _ => DohResolver.Cloudflare(),
        },
        _ => new RecursiveResolver(Server!, IsSystem ? $"this computer's DNS server {Server}" : null),
    };

    public static ResolverChoice Authoritative() => new()
    {
        Kind = ResolverKind.Authoritative,
        Display = "Authoritative: the domains' own name servers, resolved from the root",
    };

    public static ResolverChoice Doh(string provider) => new()
    {
        Kind = ResolverKind.Doh,
        DohProvider = provider,
        Display = $"DNS over HTTPS: {provider}",
    };

    public static ResolverChoice ForServer(IPAddress ip, string? note = null, bool system = false) => new()
    {
        Kind = ResolverKind.Server,
        Server = ip,
        IsSystem = system,
        Display = note is null ? ip.ToString() : $"{ip}   ({note})",
    };

    /// <summary>The list shown on the Checks page.</summary>
    public static List<ResolverChoice> All()
    {
        var list = new List<ResolverChoice> { Authoritative() };
        foreach (var (address, adapter) in NetUtil.SystemResolvers())
            list.Add(ForServer(address, $"this computer, {adapter}", system: true));
        list.Add(Doh("Cloudflare"));
        list.Add(Doh("Google"));
        list.Add(Doh("Quad9"));
        list.Add(ForServer(IPAddress.Parse("1.1.1.1"), "Cloudflare"));
        list.Add(ForServer(IPAddress.Parse("8.8.8.8"), "Google"));
        list.Add(ForServer(IPAddress.Parse("9.9.9.9"), "Quad9"));
        return list;
    }

    /// <summary>
    /// The chosen resolver first, then what to fall back to if it cannot be reached at all.
    /// The authoritative mode falls back to this computer's resolver (reachable where outbound
    /// port 53 is blocked), then to DNS over HTTPS, which passes where only a web proxy is open.
    /// </summary>
    public static List<IDnsResolver> Chain(ResolverChoice primary, bool dohFallback, TraceLog? trace = null)
    {
        var list = BuildChain(primary, dohFallback);
        foreach (var r in list) r.Trace = trace;
        return list;
    }

    private static List<IDnsResolver> BuildChain(ResolverChoice primary, bool dohFallback)
    {
        var chain = new List<IDnsResolver> { primary.Create() };
        if (primary.Kind == ResolverKind.Authoritative)
        {
            var system = NetUtil.SystemResolvers().FirstOrDefault();
            if (system.Address is not null)
                chain.Add(new RecursiveResolver(system.Address, $"this computer's DNS server {system.Address}"));
        }
        if (dohFallback)
        {
            foreach (var provider in new[] { "Cloudflare", "Google" })
            {
                if (primary.Kind == ResolverKind.Doh && primary.DohProvider == provider) continue;
                chain.Add(Doh(provider).Create());
            }
        }
        return chain;
    }
}
