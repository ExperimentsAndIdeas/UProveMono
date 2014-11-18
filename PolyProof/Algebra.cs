//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

using System;
using UProveCrypto;
using UProveCrypto.Math;
using System.Runtime.Serialization;

namespace UProveCrypto.PolyProof
{
    /// <summary>
    /// Contains a Group and its associated FieldZq
    /// </summary>
    [DataContract]
    public class Algebra
    {
        /// <summary>
        /// Group.
        /// </summary>
        public Group Group
        {
            get;
            private set;
        }

        /// <summary>
        /// FieldZq associated with Group
        /// </summary>
        public FieldZq FieldZq
        {
            get;
            private set;
        }

        /// <summary>
        /// Constructor. Takes the input group and creates the 
        /// associated FieldZq object.
        /// </summary>
        /// <param name="group"></param>
        public Algebra(Group group)
        {
            if (group == null)
            {
                throw new ArgumentNullException("Could not create Algebra because group is null.");
            }
            this.Group = group;
            try
            {
                this.FieldZq = FieldZq.CreateFieldZq(group.Q);
            }
            catch (Exception e)
            {
                throw new ArgumentException("Could not create Algebra from input group because could not create associated field.", e);
            }
        }

        [DataMember(Name = "Group", EmitDefaultValue = false, Order=1)]
        internal GroupSerializable _group;

        #region Serialization
        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            // begin by serializing the algebra context
            if (this.Group == null)
            {
                throw new SerializationException("Cannot serialize Algebra because Group is null.");
            }
            _group = new GroupSerializable(this.Group);
        }

        [OnDeserialized]
        internal void OnDeserialized(StreamingContext context)
        {
            // begin by deserializing the algebra context
            if (_group == null)
            {
                throw new SerializationException("_group cannot be null.");
            }
            this.Group = _group.ToGroup();
            this.FieldZq = FieldZq.CreateFieldZq(this.Group.Q);
        }
        #endregion

    }
}
