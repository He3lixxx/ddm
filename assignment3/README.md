## Basic Algorithm
This implementation is based on the following algorithmic idea:
- Load as many hashes as every node can hold into the memory
- Distribute all the hashes we are searching for to every worker.
- Evenly split up all hints / passwords that need to be checked and
  distribute them to the workers
- Each worker then checks its assigned range for hash matches.
  If a match is found, the master is notified

This has one main advantage: As long as all hashes we are searching
for can be kept in memory on all workers, we will only need to search
the whole range of possible hints and passwords once and find all solutions.

However, for large input data sets, it might happen that not all hashes can
be kept in memory on each node. In this case, we need to do multiple
iterations. In each iteration, each node only gets this part of the hashes.
Thus, we need to compute hashes for the same strings multiple times.
This effectively multiplies the time required for the algorithm to
finish by the count of required iterations. Thus, you want to make sure
to prevent multiple iterations as effectively as possible.

We think that this is the only solution to solve the case where the input
is too big to be kept in memory as we're not allowed to use the disk,
and doing multiple iterations where each iteration re-reads the whole file
is effectively using the disk.

#### Preventing multiple iterations
We were not allowed to change the command line interface, so we could not
provide a way to set the handling of iterations there. Thus, we added a
constant member `MAXIMUM_HASHES_TO_FIT_IN_MEMORY` to the `Master`
Actor
(`ddm/ddm-pc/src/main/java/de/hpi/ddm/actors/Master.java:53`).
Here, you need to set the count of hashes that every System can fit
in its memory. 

**Important**: If the program runs out of memory or an error is shown that multiple
iterations are necessary, please update this value to an appropriate
value for the system you are running on.

For input files that are smaller than the RAM size of the nodes, it
should be possible to prevent multiple iterations, which guarantees
minimal run times.


#### Running on clusters with significantly more workers (Odin / Thor)
Our algorithm generates a fixed set of work packets and distributes them
to the next free worker. However, if we do not have any estimation beforehand
on how many workers we can expect, we might either create way too many
work packets, resulting in much communication overhead, or way too few
work packets, resulting in workers being idle while they could be used
to speed up the process.

Currently, the project is set up to work fine with up to about 110 workers,
so for most testing environments, no changes should be required.
If you want to run this application on the Thor cluster, we would appreciate
it if you could increase the `TARGET_WORK_PACKET_COUNT` in the `Master` actor
(`ddm-pc/src/main/java/de/hpi/ddm/actors/Master.java:64`)
to the number of workers you want to start (probably 12 * 20 = 240).

#### General note
We think that this algorithm gives optimal performance for any
input data that could realistically be encountered, although you can
artificially craft input files that will take longer to process than
actually necessary (e.g. if the alphabet only allows N distinct passwords
and the file has N distinct password hashes).
We did not write logic to detect such cases as we do not expect them to
occur in any randomly generated data.

We did not specifically try to optimize for the sample input file that was
given (as we expect testing to be done with different input files). For
example, if you assume that every hash in the file is distinct and that
every hint removes a different character from the password alphabet,
you can already drastically reduce the range of possible passwords.

We did not make any such illegal assumptions about the input file that allow
to speed up the computation but result in wrong solutions for input files
where these assumptions do not hold.

If you encounter any problems or bad performance,
please contact us - we have tested some self created input files, but
might have missed some edge cases. If there are bugs that are fixable
without changing the logical concept, we'd like to fix them.

We'd also like to ask you to let us know how this implementation performs
if you run it on the RaspberryPi or the Thor cluster.