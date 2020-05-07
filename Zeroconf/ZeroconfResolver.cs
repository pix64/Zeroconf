using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using Heijden.DNS;

namespace Zeroconf
{
    /// <summary>
    ///     Looks for ZeroConf devices
    /// </summary>
    public static partial class ZeroconfResolver
    {
        static readonly AsyncLock ResolverLock = new AsyncLock();

        static readonly NetworkInterface NetworkInterface = new NetworkInterface();

        static IEnumerable<string> BrowseResponseParser(Response response)
        {
            return response.RecordsPTR.Select(ptr => ptr.PTRDNAME);
        }

        static async Task<IDictionary<string, Response>> ResolveInternal(ZeroconfOptions options,
                                                                         Action<string, Response> callback,
                                                                         CancellationToken cancellationToken)
        {
            var requestBytes = GetRequestBytes(options);
            using (options.AllowOverlappedQueries ? Disposable.Empty : await ResolverLock.LockAsync())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var dict = new Dictionary<string, Response>();

                void Converter(IPAddress address, byte[] buffer)
                {
                    var resp = new Response(buffer);
                    var firstPtr = resp.RecordsPTR.FirstOrDefault();
                    var name = firstPtr?.PTRDNAME.Split('.')[0] ?? string.Empty;
                    var addrString = address.ToString();

                    Debug.WriteLine($"IP: {addrString}, {(string.IsNullOrEmpty(name) ? string.Empty : $"Name: {name}, ")}Bytes: {buffer.Length}, IsResponse: {resp.header.QR}");

                    if (resp.header.QR)
                    {
                        var key = $"{addrString}{(string.IsNullOrEmpty(name) ? "" : $": {name}")}";
                        lock (dict)
                        {
                            dict[key] = resp;
                        }

                        callback?.Invoke(key, resp);                        
                    }
                }

                Debug.WriteLine($"Looking for {string.Join(", ", options.Protocols)} with scantime {options.ScanTime}");

                if (options.Adapter != null)
                {
                    await NetworkInterface.NetworkRequestAsync(requestBytes,
                                           options.ScanTime,
                                           options.Retries,
                                           (int)options.RetryDelay.TotalMilliseconds,
                                           Converter,
                                           options.Adapter,
                                           cancellationToken)
                      .ConfigureAwait(false);
                }
                else
                {
                    await NetworkInterface.NetworkRequestAsync(requestBytes,
                                           options.ScanTime,
                                           options.Retries,
                                           (int)options.RetryDelay.TotalMilliseconds,
                                           Converter,
                                           cancellationToken)
                      .ConfigureAwait(false);
                }

                return dict;
            }
        }

        static QType ScanQueryToQType(ScanQueryType t)
        {
            switch (t)
            {
                case ScanQueryType.Ptr:
                    return QType.PTR;
                case ScanQueryType.Srv:
                    return QType.SRV;
                case ScanQueryType.Txt:
                    return QType.TXT;
                default:
                    return QType.ANY;
            }
        }

        static byte[] GetRequestBytes(ZeroconfOptions options)
        {
            var req = new Request();
            var classType = options.ScanClassType == ScanClassType.In ? QClass.IN : QClass.ANY;

            foreach (var protocol in options.Protocols)
            {
                foreach (var queryType in options.ScanQueryTypes)
                {
                    var question = new Question(protocol, ScanQueryToQType(queryType), classType);
                    req.AddQuestion(question);
                }
            }

            return req.Data;
        }

        static ZeroconfHost ResponseToZeroconf(Response response, string remoteAddress)
        {
            var z = new ZeroconfHost
            {
                IPAddresses = response.Answers
                                      .Select(r => r.RECORD)
                                      .OfType<RecordA>()
                                      .Concat(response.Additionals
                                                      .Select(r => r.RECORD)
                                                      .OfType<RecordA>())
                                      .Select(aRecord => aRecord.Address)
                                      .Distinct()
                                      .ToList(),
            };

            z.Id = z.IPAddresses.FirstOrDefault() ?? remoteAddress;

            var dispNameSet = false;

            foreach (var ptrRec in response.RecordsPTR)
            {
                z.AddDomainName(ptrRec.PTRDNAME);

                // set the display name if needed
                if (!dispNameSet)
                {
                    z.DisplayName = ptrRec.PTRDNAME.Split('.')[0];
                    dispNameSet = true;
                }
            }

            if (response.RecordsRR.Where(x => x.Type == Heijden.DNS.Type.SRV).FirstOrDefault()?.RECORD is RecordSRV srvRec)
            {
                var svc = new Service
                {
                    Name = srvRec.RR.NAME,
                    Port = srvRec.PORT,
                    Ttl = (int)srvRec.RR.TTL,
                };

                z.AddDomainName(srvRec.RR.NAME);

                if (!dispNameSet)
                {
                    z.DisplayName = srvRec.RR.NAME.Split('.')[0];
                    dispNameSet = true;
                }

                z.AddService(svc);
            }

            if (response.RecordsRR.Where(x => x.Type == Heijden.DNS.Type.TXT).FirstOrDefault()?.RECORD is RecordTXT txtRec)
            {

                var txr = new TextRecord
                {
                    Name = txtRec.RR.NAME,
                    Ttl = (int)txtRec.RR.TTL,
                };

                z.AddDomainName(txtRec.RR.NAME);

                if (!dispNameSet)
                {
                    z.DisplayName = txtRec.RR.NAME.Split('.')[0];
                    dispNameSet = true;
                }

                foreach (var txt in txtRec.TXT)
                {
                    var split = txt.Split(new[] { '=' }, 2);
                    if (split.Length == 1)
                    {
                        if (!string.IsNullOrWhiteSpace(split[0]))
                            txr.AddProperty(split[0], null);
                    }
                    else
                    {
                        txr.AddProperty(split[0], split[1].TrimEnd(new[] { '\0' }));
                    }
                }

                z.AddTextRecord(txr);
            }

            return z;
        }
    }
}
