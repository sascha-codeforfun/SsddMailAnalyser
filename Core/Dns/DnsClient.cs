using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;

namespace SsddMailAnalyser.Core.Dns;

/// <summary>
/// The DNS front end every check uses: a cache for one analysis, a log for the report, and a
/// chain of resolvers. When the first one cannot be reached at all (port 53 blocked on an
/// isolated system, say), it moves to the next and records that it did. A resolver that has
/// answered once is never abandoned: from then on a timeout is about the name, not the path.
///
/// Synchronous on purpose: every caller runs on the busy overlay's worker thread.
/// </summary>
public sealed class DnsClient
{
    private readonly Dictionary<(string, DnsType), DnsResponse> _cache = new();
    private readonly List<string> _log = new();
    private readonly List<string> _fallbacks = new();
    private readonly List<IDnsResolver> _chain;
    private readonly object _gate = new();
    private int _current;

    public DnsClient(IEnumerable<IDnsResolver> chain)
    {
        _chain = chain.ToList();
        if (_chain.Count == 0) throw new ArgumentException("at least one resolver is needed", nameof(chain));
    }

    public DnsClient(IPAddress server) : this(new IDnsResolver[] { new RecursiveResolver(server) })
    {
    }

    public IDnsResolver Active
    {
        get { lock (_gate) return _chain[_current]; }
    }

    /// <summary>The iterative resolver, while it is the one in use.</summary>
    public IterativeResolver? Authoritative => Active as IterativeResolver;

    /// <summary>"Switched from X to Y because ..." lines.</summary>
    public IReadOnlyList<string> Fallbacks
    {
        get { lock (_gate) return _fallbacks.ToList(); }
    }

    /// <summary>Every query that went to the wire, with its outcome. For the report.</summary>
    public IReadOnlyList<string> Log
    {
        get { lock (_gate) return _log.ToList(); }
    }

    // A name every working resolver finds, and one that cannot exist (RFC 6761).
    private const string CanaryName = "a.root-servers.net";
    private const string AbsentName = "ssdd-probe.invalid";

    private readonly List<string> _pathProblems = new();
    private string? _blocked;
    private string? _unavailable;

    /// <summary>Why the probe found no resolver that gives usable answers, when it found none.</summary>
    public string? Unavailable
    {
        get { lock (_gate) return _unavailable; }
    }

    /// <summary>What is wrong with the resolver in use when there was none better to move to.</summary>
    public IReadOnlyList<string> PathProblems
    {
        get { lock (_gate) return _pathProblems.ToList(); }
    }

    /// <summary>Set when authoritative resolution found port 53 answered by something else.</summary>
    public string? Interception
    {
        get { lock (_gate) return _chain.OfType<IterativeResolver>().Select(r => r.Interception).FirstOrDefault(i => i is not null); }
    }

    /// <summary>
    /// Run once before the checks: is the resolver in use giving real DNS? It must find a name
    /// that always exists and must not find one that cannot. A resolver that fails either way
    /// (a filtered network that answers NXDOMAIN to everything, a provider that rewrites
    /// NXDOMAIN into an address) is left for the next one in the chain. If there is no next
    /// one and it finds nothing at all, no DNS check is run: "the domain does not exist" must
    /// never be concluded from such answers.
    /// </summary>
    public void Probe(CancellationToken cancel = default)
    {
        while (true)
        {
            cancel.ThrowIfCancellationRequested();
            IDnsResolver resolver;
            IDnsResolver? next;
            lock (_gate)
            {
                resolver = _chain[_current];
                next = _current < _chain.Count - 1 ? _chain[_current + 1] : null;
            }

            var present = resolver.Resolve(CanaryName, DnsType.A, cancel);
            string? problem = null;
            bool findsNothing = false;
            bool transport = false;
            if (present.TransportFailure)
            {
                problem = present.Error ?? "no answer";
                transport = true;
            }
            else if (present.IsEmpty || present.IsOk && present.Addresses().Count == 0)
            {
                problem = $"it says {CanaryName} does not exist";
                findsNothing = true;
            }
            else if (present.IsOk)
            {
                var absent = resolver.Resolve(AbsentName, DnsType.A, cancel);
                if (absent.TransportFailure)
                {
                    problem = absent.Error ?? "no answer";
                    transport = true;
                }
                else if (absent.IsOk && absent.Addresses().Count > 0)
                {
                    problem = $"it answers {absent.Addresses()[0]} for {AbsentName}, a name that cannot exist";
                }
            }
            // SERVFAIL or a timeout on the probe from a resolver that is reachable says nothing either way.
            if (problem is null) return;

            lock (_gate)
            {
                if (next is not null)
                {
                    var line = transport
                        ? $"{resolver.Label} could not be reached ({problem}); switched to {next.Label}."
                        : $"{resolver.Label} does not give real DNS answers ({problem}); switched to {next.Label}.";
                    _fallbacks.Add(line);
                    _log.Add("!     " + line);
                    _current++;
                    continue;
                }
                if (transport)
                {
                    _unavailable = $"{resolver.Label}: {problem}";
                    return;   // every query will say so itself
                }
                if (findsNothing)
                {
                    _unavailable = $"{resolver.Label}: {problem}";
                    _blocked = $"no trustworthy DNS from this machine: {resolver.Label} finds nothing ({problem})";
                    _pathProblems.Add($"{resolver.Label} does not give real DNS answers: {problem}. There was no other resolver to move to, so the DNS checks were not run rather than built on these answers.");
                }
                else
                {
                    _pathProblems.Add($"{resolver.Label} rewrites answers: {problem}. There was no other resolver to move to, so 'no such record' and 'not listed' results from it are unreliable.");
                }
                _log.Add("!     " + _pathProblems[^1]);
                return;
            }
        }
    }

    public void Note(string line)
    {
        lock (_gate) _log.Add(line);
    }

    public DnsResponse Query(string name, DnsType type, CancellationToken cancel = default)
    {
        name = Normalize(name);
        lock (_gate)
        {
            if (_cache.TryGetValue((name, type), out var cached)) return cached;
        }

        string? blocked;
        lock (_gate) blocked = _blocked;

        DnsResponse response;
        if (blocked is not null)
        {
            return new DnsResponse { Name = name, Type = type, Status = DnsStatus.Error, Error = blocked, Via = Active.Label };
        }
        if (name.Length == 0 || name.Length > 253 || name.Split('.').Any(l => l.Length == 0 || l.Length > 63))
        {
            response = new DnsResponse { Name = name, Type = type, Status = DnsStatus.Error, Error = "invalid name" };
        }
        else
        {
            while (true)
            {
                cancel.ThrowIfCancellationRequested();
                IDnsResolver resolver;
                lock (_gate) resolver = _chain[_current];
                response = resolver.Resolve(name, type, cancel);

                bool canFallBack;
                lock (_gate) canFallBack = _current < _chain.Count - 1;
                if (response.TransportFailure && canFallBack)
                {
                    lock (_gate)
                    {
                        var next = _chain[_current + 1];
                        _fallbacks.Add($"{resolver.Label} could not be reached ({response.Error}); switched to {next.Label}.");
                        _log.Add($"!     {resolver.Label} unreachable ({response.Error}) -> using {next.Label}");
                        _current++;
                    }
                    continue;
                }
                break;
            }
        }

        lock (_gate)
        {
            _cache[(name, type)] = response;
            _log.Add($"{type,-5} {name}  ->  {response.Describe()}");
        }
        return response;
    }

    /// <summary>Whether an answer for this name is already at hand (no query needed).</summary>
    public bool IsCached(string name, DnsType type)
    {
        lock (_gate) return _cache.ContainsKey((Normalize(name), type));
    }

    /// <summary>A, then AAAA; returns every address found.</summary>
    public List<IPAddress> Addresses(string name, CancellationToken cancel = default)
    {
        var list = new List<IPAddress>();
        list.AddRange(Query(name, DnsType.A, cancel).Addresses());
        list.AddRange(Query(name, DnsType.AAAA, cancel).Addresses());
        return list;
    }

    public static string Normalize(string name) => DnsWire.Normalize(name);
}
