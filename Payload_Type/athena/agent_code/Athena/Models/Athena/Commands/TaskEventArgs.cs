﻿using Athena.Models.Mythic.Response;
using Athena.Models.Mythic.Tasks;
using System;

namespace Athena.Models.Athena.Commands
{
    public class TaskEventArgs : EventArgs
    {
        public MythicJob job { get; set; }

        public TaskEventArgs (MythicJob job)
        {
            this.job = job;
        }
    }

    public class SocksEventArgs : EventArgs
    {
        public SocksMessage sm { get; set; }

        public SocksEventArgs(SocksMessage sm)
        {
            this.sm = sm;
        }
    }
}
