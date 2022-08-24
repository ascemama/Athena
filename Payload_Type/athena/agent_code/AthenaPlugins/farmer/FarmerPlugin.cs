﻿using PluginBase;
namespace Plugin
{
    public class FarmerPlugin
    {
        private static Farmer farm = new Farmer();

        public static void Execute(Dictionary<string, object> args)
        {

            if (!int.TryParse((string)args["port"], out Config.port))
            {
                farm.Stop();

                PluginHandler.AddResponse(new ResponseResult()
                {
                    task_id = (string)args["task-id"],
                    completed = "true",
                    user_output = "Stopped Farmer."
                });
            }
            else {
                Config.task_id = (string)args["task-id"];
                PluginHandler.WriteOutput($"Starting farmer on port: {Config.port}", Config.task_id, false);
                farm.Initialize(Config.port);
            }
        }
    }
}